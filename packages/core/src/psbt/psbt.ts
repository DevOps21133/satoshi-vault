/**
 * BIP174 Partially Signed Bitcoin Transactions (v0) with BIP371 taproot
 * fields, implemented from the specs:
 *   https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
 *   https://github.com/bitcoin/bips/blob/master/bip-0371.mediawiki
 *
 * Scope: single-sig wallets (P2PKH, P2SH-P2WPKH, P2WPKH, P2TR key-path).
 * That scope is a security decision — a smaller finalizer is an auditable
 * finalizer. Unknown key types are preserved on parse/serialize (combiner
 * compatibility) but never interpreted.
 *
 * Security decisions:
 * - All parsing treats input as hostile: duplicate keys rejected, map counts
 *   must match the unsigned tx, lengths validated before reads.
 * - The signer NEVER trusts PSBT-provided scripts or amounts blindly:
 *   * The derivation path must match the wallet's own policy (purpose/coin
 *     type/account structure) — this stops a malicious PSBT from steering
 *     signing to an unexpected key (attack seen against hardware wallets).
 *   * The prevout script must be recomputed from the derived key and match.
 *   * For legacy inputs the full previous transaction is required and its
 *     txid must match the input's prevTxid (fee-forgery defense; the legacy
 *     sighash does not commit to amounts).
 *   * Only SIGHASH_ALL / SIGHASH_DEFAULT are ever signed.
 * - Fee must be computable (all prevout amounts known) and non-negative
 *   before any signature is produced.
 */

import { secp256k1, schnorr } from "@noble/curves/secp256k1";
import { base64 } from "@scure/base";
import { ByteReader, ByteWriter } from "../util/writer.js";
import { bytesEqual, bytesToHex, concatBytes, u32be, zeroize } from "../util/bytes.js";
import { hash160, sha256d } from "../crypto/hash.js";
import {
  Transaction,
  TxOutput,
  parseTx,
  serializeTxLegacy,
  assertSaneOutput,
  MAX_MONEY,
} from "../tx/tx.js";
import {
  legacySighash,
  segwitV0Sighash,
  taprootSighash,
  p2pkhScriptCode,
  SIGHASH_ALL,
  SIGHASH_DEFAULT,
} from "../tx/sighash.js";
import { ecdsaSignChecked, schnorrSignChecked, SpendType } from "../tx/sign.js";
import { taprootTweakPrivateKey, xOnly } from "../crypto/taproot.js";
import { HDPrivateKey, HARDENED_OFFSET } from "../bip32/hdkey.js";
import { Network, MAINNET } from "../address/network.js";

// --- key types ---------------------------------------------------------------

export const PSBT_GLOBAL_UNSIGNED_TX = 0x00;
export const PSBT_GLOBAL_VERSION = 0xfb;

export const PSBT_IN_NON_WITNESS_UTXO = 0x00;
export const PSBT_IN_WITNESS_UTXO = 0x01;
export const PSBT_IN_PARTIAL_SIG = 0x02;
export const PSBT_IN_SIGHASH_TYPE = 0x03;
export const PSBT_IN_REDEEM_SCRIPT = 0x04;
export const PSBT_IN_BIP32_DERIVATION = 0x06;
export const PSBT_IN_FINAL_SCRIPTSIG = 0x07;
export const PSBT_IN_FINAL_SCRIPTWITNESS = 0x08;
export const PSBT_IN_TAP_KEY_SIG = 0x13;
export const PSBT_IN_TAP_BIP32_DERIVATION = 0x16;
export const PSBT_IN_TAP_INTERNAL_KEY = 0x17;

export const PSBT_OUT_REDEEM_SCRIPT = 0x00;
export const PSBT_OUT_BIP32_DERIVATION = 0x02;
export const PSBT_OUT_TAP_INTERNAL_KEY = 0x05;
export const PSBT_OUT_TAP_BIP32_DERIVATION = 0x07;

const PSBT_MAGIC = new Uint8Array([0x70, 0x73, 0x62, 0x74, 0xff]);
const MAX_KEY_LENGTH = 10_000;

// --- structure ---------------------------------------------------------------

export interface KeyPair {
  /** keytype byte followed by keydata. */
  key: Uint8Array;
  value: Uint8Array;
}

export interface Psbt {
  /** The unsigned transaction (empty scriptSigs, no witnesses). */
  tx: Transaction;
  globalMap: KeyPair[];
  inputMaps: KeyPair[][];
  outputMaps: KeyPair[][];
}

function findOne(map: KeyPair[], key: Uint8Array): Uint8Array | undefined {
  for (const kp of map) if (bytesEqual(kp.key, key)) return kp.value;
  return undefined;
}

function findByType(map: KeyPair[], type: number): KeyPair[] {
  return map.filter((kp) => kp.key[0] === type);
}

function typeKey(type: number): Uint8Array {
  return new Uint8Array([type]);
}

/** Insert or replace the pair with this exact key. */
export function setKeyPair(map: KeyPair[], key: Uint8Array, value: Uint8Array): void {
  for (const kp of map) {
    if (bytesEqual(kp.key, key)) {
      kp.value = value;
      return;
    }
  }
  map.push({ key, value });
}

function removeType(map: KeyPair[], type: number): void {
  for (let i = map.length - 1; i >= 0; i--) {
    if (map[i]!.key[0] === type) map.splice(i, 1);
  }
}

// --- parse / serialize -------------------------------------------------------

function readMap(r: ByteReader): KeyPair[] {
  const map: KeyPair[] = [];
  const seen = new Set<string>();
  for (;;) {
    const keyLen = r.varInt();
    if (keyLen === 0n) return map;
    if (keyLen > BigInt(MAX_KEY_LENGTH)) throw new Error("PSBT key too long");
    const key = r.bytes(Number(keyLen));
    const value = r.varBytes();
    const id = bytesToHex(key);
    if (seen.has(id)) throw new Error("duplicate key in PSBT map");
    seen.add(id);
    map.push({ key, value });
  }
}

function writeMap(w: ByteWriter, map: KeyPair[]): void {
  for (const kp of map) {
    if (kp.key.length === 0) throw new Error("empty PSBT key");
    w.varBytes(kp.key).varBytes(kp.value);
  }
  w.u8(0x00);
}

export function parsePsbt(raw: Uint8Array): Psbt {
  const r = new ByteReader(raw);
  const magic = r.bytes(5);
  if (!bytesEqual(magic, PSBT_MAGIC)) throw new Error("not a PSBT (bad magic)");

  const globalMap = readMap(r);

  const version = findOne(globalMap, typeKey(PSBT_GLOBAL_VERSION));
  if (version) {
    if (version.length !== 4) throw new Error("malformed PSBT_GLOBAL_VERSION");
    const v = new DataView(version.buffer, version.byteOffset, 4).getUint32(0, true);
    if (v !== 0) throw new Error(`unsupported PSBT version ${v}`);
  }

  const rawTx = findOne(globalMap, typeKey(PSBT_GLOBAL_UNSIGNED_TX));
  if (!rawTx) throw new Error("PSBT missing unsigned transaction");
  const tx = parseTx(rawTx);
  for (const input of tx.inputs) {
    if (input.scriptSig.length !== 0 || input.witness.length !== 0) {
      throw new Error("PSBT unsigned tx must have empty scriptSigs and no witnesses");
    }
  }

  const inputMaps: KeyPair[][] = [];
  for (let i = 0; i < tx.inputs.length; i++) inputMaps.push(readMap(r));
  const outputMaps: KeyPair[][] = [];
  for (let i = 0; i < tx.outputs.length; i++) outputMaps.push(readMap(r));
  if (!r.isDone()) throw new Error("trailing bytes after PSBT");

  // Two inputs spending the SAME outpoint would be counted twice by psbtFee, so
  // a transaction spending one 100k-sat coin "twice" can be presented to the
  // human reviewer with a perfectly plausible fee. Every signature would be
  // valid and the transaction still consensus-invalid: the user completes the
  // whole air-gap ceremony for something that can never confirm.
  const outpoints = new Set<string>();
  for (const input of tx.inputs) {
    const id = `${bytesToHex(input.prevTxid)}:${input.prevVout}`;
    if (outpoints.has(id)) throw new Error("PSBT spends the same outpoint twice");
    outpoints.add(id);
  }

  const psbt: Psbt = { tx, globalMap, inputMaps, outputMaps };
  // Validate any provided utxo fields up front so garbage fails fast.
  for (let i = 0; i < tx.inputs.length; i++) resolvePrevout(psbt, i);
  return psbt;
}

export function serializePsbt(psbt: Psbt): Uint8Array {
  const w = new ByteWriter();
  w.bytes(PSBT_MAGIC);
  // Keep the unsigned tx in the global map current.
  setKeyPair(psbt.globalMap, typeKey(PSBT_GLOBAL_UNSIGNED_TX), serializeTxLegacy(psbt.tx));
  writeMap(w, psbt.globalMap);
  for (const map of psbt.inputMaps) writeMap(w, map);
  for (const map of psbt.outputMaps) writeMap(w, map);
  return w.finish();
}

export function psbtToBase64(psbt: Psbt): string {
  return base64.encode(serializePsbt(psbt));
}

export function psbtFromBase64(s: string): Psbt {
  return parsePsbt(base64.decode(s.trim()));
}

/** Fresh PSBT around an unsigned transaction. */
export function createPsbt(tx: Transaction): Psbt {
  for (const input of tx.inputs) {
    if (input.scriptSig.length !== 0 || input.witness.length !== 0) {
      throw new Error("createPsbt requires an unsigned transaction");
    }
  }
  return {
    tx,
    globalMap: [{ key: typeKey(PSBT_GLOBAL_UNSIGNED_TX), value: serializeTxLegacy(tx) }],
    inputMaps: tx.inputs.map(() => []),
    outputMaps: tx.outputs.map(() => []),
  };
}

// --- typed field accessors ---------------------------------------------------

export interface Bip32Derivation {
  /** 33-byte compressed pubkey (or 32-byte x-only for taproot). */
  pubkey: Uint8Array;
  masterFingerprint: number;
  path: number[];
}

function parseDerivationValue(value: Uint8Array): { masterFingerprint: number; path: number[] } {
  if (value.length < 4 || (value.length - 4) % 4 !== 0) throw new Error("malformed BIP32 derivation");
  const view = new DataView(value.buffer, value.byteOffset, value.byteLength);
  const masterFingerprint = view.getUint32(0, false);
  // Depth is known from the length — check it BEFORE materialising the array.
  if ((value.length - 4) / 4 > 255) throw new Error("derivation path too deep");
  const path: number[] = [];
  for (let off = 4; off < value.length; off += 4) path.push(view.getUint32(off, true));
  return { masterFingerprint, path };
}

function serializeDerivationValue(masterFingerprint: number, path: number[]): Uint8Array {
  const w = new ByteWriter();
  w.bytes(u32be(masterFingerprint));
  for (const index of path) w.u32le(index);
  return w.finish();
}

export function getBip32Derivations(map: KeyPair[]): Bip32Derivation[] {
  return findByType(map, PSBT_IN_BIP32_DERIVATION).map((kp) => {
    const pubkey = kp.key.slice(1);
    if (pubkey.length !== 33) throw new Error("BIP32 derivation key must be a 33-byte pubkey");
    return { pubkey, ...parseDerivationValue(kp.value) };
  });
}

export function getTapBip32Derivations(map: KeyPair[]): Bip32Derivation[] {
  return findByType(map, PSBT_IN_TAP_BIP32_DERIVATION).map((kp) => {
    const pubkey = kp.key.slice(1);
    if (pubkey.length !== 32) throw new Error("taproot derivation key must be a 32-byte x-only pubkey");
    const r = new ByteReader(kp.value);
    const numHashes = r.varInt();
    if (numHashes !== 0n) throw new Error("taproot script-path leaves are not supported (key-path only)");
    const rest = r.bytes(r.remaining);
    return { pubkey, ...parseDerivationValue(rest) };
  });
}

export function setBip32Derivation(map: KeyPair[], d: Bip32Derivation): void {
  if (d.pubkey.length !== 33) throw new Error("pubkey must be 33 bytes");
  setKeyPair(
    map,
    concatBytes(typeKey(PSBT_IN_BIP32_DERIVATION), d.pubkey),
    serializeDerivationValue(d.masterFingerprint, d.path),
  );
}

export function setTapBip32Derivation(map: KeyPair[], d: Bip32Derivation): void {
  if (d.pubkey.length !== 32) throw new Error("x-only pubkey must be 32 bytes");
  const value = concatBytes(new Uint8Array([0x00]), serializeDerivationValue(d.masterFingerprint, d.path));
  setKeyPair(map, concatBytes(typeKey(PSBT_IN_TAP_BIP32_DERIVATION), d.pubkey), value);
}

/**
 * Output-map derivation fields (BIP174 PSBT_OUT_BIP32_DERIVATION = 0x02 and
 * BIP371 PSBT_OUT_TAP_BIP32_DERIVATION = 0x07 — note these differ from the
 * input-map key types). Used to declare change outputs so the signer can
 * verify them against its own keys.
 */
export function getOutBip32Derivations(map: KeyPair[]): Bip32Derivation[] {
  return findByType(map, PSBT_OUT_BIP32_DERIVATION).map((kp) => {
    const pubkey = kp.key.slice(1);
    if (pubkey.length !== 33) throw new Error("BIP32 derivation key must be a 33-byte pubkey");
    return { pubkey, ...parseDerivationValue(kp.value) };
  });
}

export function getOutTapBip32Derivations(map: KeyPair[]): Bip32Derivation[] {
  return findByType(map, PSBT_OUT_TAP_BIP32_DERIVATION).map((kp) => {
    const pubkey = kp.key.slice(1);
    if (pubkey.length !== 32) throw new Error("taproot derivation key must be a 32-byte x-only pubkey");
    const r = new ByteReader(kp.value);
    const numHashes = r.varInt();
    if (numHashes !== 0n) throw new Error("taproot script-path leaves are not supported (key-path only)");
    const rest = r.bytes(r.remaining);
    return { pubkey, ...parseDerivationValue(rest) };
  });
}

export function setOutBip32Derivation(map: KeyPair[], d: Bip32Derivation): void {
  if (d.pubkey.length !== 33) throw new Error("pubkey must be 33 bytes");
  setKeyPair(
    map,
    concatBytes(typeKey(PSBT_OUT_BIP32_DERIVATION), d.pubkey),
    serializeDerivationValue(d.masterFingerprint, d.path),
  );
}

export function setOutTapBip32Derivation(map: KeyPair[], d: Bip32Derivation): void {
  if (d.pubkey.length !== 32) throw new Error("x-only pubkey must be 32 bytes");
  const value = concatBytes(new Uint8Array([0x00]), serializeDerivationValue(d.masterFingerprint, d.path));
  setKeyPair(map, concatBytes(typeKey(PSBT_OUT_TAP_BIP32_DERIVATION), d.pubkey), value);
}

export function setWitnessUtxo(map: KeyPair[], utxo: TxOutput): void {
  assertSaneOutput(utxo);
  const w = new ByteWriter();
  w.u64le(utxo.value).varBytes(utxo.scriptPubKey);
  setKeyPair(map, typeKey(PSBT_IN_WITNESS_UTXO), w.finish());
}

export function setNonWitnessUtxo(map: KeyPair[], rawTx: Uint8Array): void {
  parseTx(rawTx); // must be well-formed
  setKeyPair(map, typeKey(PSBT_IN_NON_WITNESS_UTXO), rawTx);
}

export function setRedeemScript(map: KeyPair[], redeem: Uint8Array): void {
  setKeyPair(map, typeKey(PSBT_IN_REDEEM_SCRIPT), redeem);
}

export function setTapInternalKey(map: KeyPair[], xonly: Uint8Array): void {
  if (xonly.length !== 32) throw new Error("internal key must be 32 bytes");
  setKeyPair(map, typeKey(PSBT_IN_TAP_INTERNAL_KEY), xonly);
}

// --- prevout resolution ------------------------------------------------------

/**
 * The spent output for input `index`, from witness_utxo or non_witness_utxo.
 * When a full previous transaction is present its txid MUST match the input's
 * prevTxid (otherwise an attacker could lie about the amount being spent and
 * trick the signer into burning funds as fees).
 */
export function resolvePrevout(psbt: Psbt, index: number): TxOutput | undefined {
  const input = psbt.tx.inputs[index];
  const map = psbt.inputMaps[index];
  if (!input || !map) throw new Error("input index out of range");

  const nonWitness = findOne(map, typeKey(PSBT_IN_NON_WITNESS_UTXO));
  let fromFullTx: TxOutput | undefined;
  if (nonWitness) {
    const prevTx = parseTx(nonWitness);
    const prevTxid = sha256d(serializeTxLegacy(prevTx));
    if (!bytesEqual(prevTxid, input.prevTxid)) {
      throw new Error("non_witness_utxo txid does not match input");
    }
    const out = prevTx.outputs[input.prevVout];
    if (!out) throw new Error("input vout beyond previous transaction outputs");
    fromFullTx = out;
  }

  const witnessUtxo = findOne(map, typeKey(PSBT_IN_WITNESS_UTXO));
  if (witnessUtxo) {
    const r = new ByteReader(witnessUtxo);
    const value = r.u64le();
    const scriptPubKey = r.varBytes();
    if (!r.isDone()) throw new Error("trailing bytes in witness_utxo");
    const out = { value, scriptPubKey };
    assertSaneOutput(out);
    if (fromFullTx && (fromFullTx.value !== out.value || !bytesEqual(fromFullTx.scriptPubKey, out.scriptPubKey))) {
      throw new Error("witness_utxo disagrees with non_witness_utxo");
    }
    return out;
  }
  return fromFullTx;
}

/** Total fee. Throws unless every input's prevout amount is known. */
export function psbtFee(psbt: Psbt): bigint {
  let inputSum = 0n;
  for (let i = 0; i < psbt.tx.inputs.length; i++) {
    const prevout = resolvePrevout(psbt, i);
    if (!prevout) throw new Error(`input ${i} has no utxo information`);
    inputSum += prevout.value;
  }
  let outputSum = 0n;
  for (const out of psbt.tx.outputs) outputSum += out.value;
  const fee = inputSum - outputSum;
  if (fee < 0n) throw new Error("outputs exceed inputs (negative fee)");
  if (fee > MAX_MONEY) throw new Error("fee out of range");
  return fee;
}

// --- script classification ---------------------------------------------------

export interface ClassifiedInput {
  spendType: SpendType;
  prevout: TxOutput;
  /** For p2sh-p2wpkh: the 0014{20} redeem script. */
  redeemScript?: Uint8Array;
}

export function classifyInput(psbt: Psbt, index: number): ClassifiedInput {
  const prevout = resolvePrevout(psbt, index);
  if (!prevout) throw new Error(`input ${index} has no utxo information`);
  const map = psbt.inputMaps[index]!;
  const script = prevout.scriptPubKey;

  if (script.length === 25 && script[0] === 0x76 && script[1] === 0xa9 && script[2] === 0x14 && script[23] === 0x88 && script[24] === 0xac) {
    return { spendType: "p2pkh", prevout };
  }
  if (script.length === 22 && script[0] === 0x00 && script[1] === 0x14) {
    return { spendType: "p2wpkh", prevout };
  }
  if (script.length === 34 && script[0] === 0x51 && script[1] === 0x20) {
    return { spendType: "p2tr", prevout };
  }
  if (script.length === 23 && script[0] === 0xa9 && script[1] === 0x14 && script[22] === 0x87) {
    const redeem = findOne(map, typeKey(PSBT_IN_REDEEM_SCRIPT));
    if (!redeem) throw new Error("p2sh input missing redeem script");
    if (!(redeem.length === 22 && redeem[0] === 0x00 && redeem[1] === 0x14)) {
      throw new Error("only P2SH-P2WPKH redeem scripts are supported");
    }
    if (!bytesEqual(script.slice(2, 22), hash160(redeem))) {
      throw new Error("redeem script does not hash to the scriptPubKey");
    }
    return { spendType: "p2sh-p2wpkh", prevout, redeemScript: redeem };
  }
  throw new Error("unsupported scriptPubKey type");
}

// --- signing -----------------------------------------------------------------

const PURPOSE_FOR_SPEND_TYPE: Record<SpendType, number> = {
  p2pkh: 44,
  "p2sh-p2wpkh": 49,
  p2wpkh: 84,
  p2tr: 86,
};

/**
 * Wallet path policy for single-sig accounts:
 *   m / purpose' / coin_type' / account' / change / index
 * The purpose must match the script type being spent and the coin type must
 * match the network. This is the anti-steering defense: a hostile PSBT cannot
 * make the signer use keys outside its declared account structure.
 */
export function validateSigningPath(path: number[], spendType: SpendType, network: Network): void {
  if (path.length !== 5) throw new Error("derivation path must have 5 levels (BIP44 structure)");
  const [purpose, coin, account, change, index] = path as [number, number, number, number, number];
  const expectedPurpose = PURPOSE_FOR_SPEND_TYPE[spendType] + HARDENED_OFFSET;
  if (purpose !== expectedPurpose) {
    throw new Error(`derivation purpose does not match script type (expected ${PURPOSE_FOR_SPEND_TYPE[spendType]}')`);
  }
  const expectedCoin = (network.name === MAINNET.name ? 0 : 1) + HARDENED_OFFSET;
  if (coin !== expectedCoin) throw new Error("derivation coin type does not match network");
  if (account < HARDENED_OFFSET) throw new Error("account level must be hardened");
  if (account - HARDENED_OFFSET > 100_000) throw new Error("implausible account index");
  if (change !== 0 && change !== 1) throw new Error("change level must be 0 or 1");
  if (index >= HARDENED_OFFSET) throw new Error("address index must be non-hardened");
  if (index > 100_000) throw new Error("implausible address index");
}

function deriveByIndices(master: HDPrivateKey, path: number[]): HDPrivateKey {
  let node = master;
  for (const index of path) {
    const next = node.deriveChild(index);
    if (node !== master) node.wipe();
    node = next;
  }
  return node;
}

export interface SignPsbtResult {
  /** Input indices signed with keys from this master. */
  signedInputs: number[];
  fee: bigint;
}

/**
 * Sign every input that belongs to `master` (matched by fingerprint) under
 * the wallet path policy. Inputs owned by other wallets are left untouched.
 *
 * Scope, so callers do not assume protection that lives elsewhere: this
 * function enforces *cryptographic* correctness (amounts committed by the
 * sighash, prevouts verified against their txids, paths matched to the script
 * type, signatures verified after signing). It deliberately applies NO policy
 * about what the transaction means — there is no fee ceiling and no change
 * verification here. Those are human decisions and live in the Signer's review
 * screen, which shows the destination, the change re-derivation result and the
 * fee, and demands a second confirmation for an abnormal fee.
 */
export function signPsbt(psbt: Psbt, master: HDPrivateKey, network: Network): SignPsbtResult {
  // Fee must be fully known before we sign anything at all.
  const fee = psbtFee(psbt);
  const masterFingerprint = master.fingerprint;
  const signedInputs: number[] = [];

  for (let i = 0; i < psbt.tx.inputs.length; i++) {
    const map = psbt.inputMaps[i]!;
    const { spendType, prevout } = classifyInput(psbt, i);

    // Neither the legacy nor the BIP143 sighash lets the network reject a
    // lied-about amount for OTHER inputs, and BIP143 commits only to the
    // amount the wallet CLAIMS for this input. A bare witness_utxo is
    // therefore attacker-controlled data. Require the full previous
    // transaction (hash-bound to prevTxid in resolvePrevout) for every
    // non-taproot input. Taproot is exempt: BIP341 commits to every prevout
    // amount and script, so a lie produces an invalid transaction.
    if (spendType !== "p2tr" && !findOne(map, typeKey(PSBT_IN_NON_WITNESS_UTXO))) {
      throw new Error(`input ${i}: ${spendType} input requires non_witness_utxo (amount forgery defense)`);
    }

    const declaredSighash = findOne(map, typeKey(PSBT_IN_SIGHASH_TYPE));
    if (declaredSighash) {
      if (declaredSighash.length !== 4) throw new Error("malformed sighash type");
      const t = new DataView(declaredSighash.buffer, declaredSighash.byteOffset, 4).getUint32(0, true);
      const allowed = spendType === "p2tr" ? t === SIGHASH_DEFAULT || t === SIGHASH_ALL : t === SIGHASH_ALL;
      if (!allowed) throw new Error(`refusing sighash type 0x${t.toString(16)}`);
    }

    // A malformed derivation entry belongs to whoever wrote it — it must not
    // take down the signing of inputs that are perfectly fine, including inputs
    // this wallet does not even own.
    let derivations: Bip32Derivation[];
    try {
      derivations = spendType === "p2tr" ? getTapBip32Derivations(map) : getBip32Derivations(map);
    } catch {
      continue;
    }
    const ours = derivations.filter((d) => d.masterFingerprint === masterFingerprint);
    if (ours.length === 0) continue;

    // Master fingerprints are only 32 bits and are PUBLIC, so anyone can write
    // an entry carrying ours. An entry whose key we cannot reproduce is treated
    // as someone else's and skipped, never as fatal — otherwise a hostile PSBT
    // could block signing entirely by listing one forged entry first.
    //
    // Order matters here: the path policy is enforced only AFTER the key is
    // proven to be ours. Checking it first would let a forged, policy-violating
    // entry throw out of the whole call (a denial of service the PSBT author
    // fully controls, since they control the byte order of the map).
    let child: HDPrivateKey | undefined;
    let pubkey: Uint8Array | undefined;
    for (const derivation of ours) {
      // Cheap structural bound before any elliptic-curve work: every path this
      // wallet can sign is exactly 5 levels, so a forged 255-level entry costs
      // nothing to reject and cannot be used to burn CPU.
      if (derivation.path.length !== 5) continue;
      const candidate = deriveByIndices(master, derivation.path);
      const candidatePubkey = candidate.publicKey;
      const expectedPubkey = spendType === "p2tr" ? xOnly(candidatePubkey) : candidatePubkey;
      if (bytesEqual(expectedPubkey, derivation.pubkey)) {
        // Proven ours: from here a policy violation IS fatal, because it means
        // someone is trying to steer this vault's own key off its wallet paths.
        try {
          validateSigningPath(derivation.path, spendType, network);
        } catch (e) {
          candidate.wipe();
          throw e;
        }
        child = candidate;
        pubkey = candidatePubkey;
        break;
      }
      candidate.wipe();
    }
    if (!child || !pubkey) continue;

    try {
      switch (spendType) {
        case "p2pkh": {
          const expected = p2pkhScriptCode(hash160(pubkey));
          if (!bytesEqual(prevout.scriptPubKey, expected)) {
            throw new Error(`input ${i}: prevout script does not match the signing key`);
          }
          const sighash = legacySighash(psbt.tx, i, prevout.scriptPubKey, SIGHASH_ALL);
          const sig = ecdsaSignChecked(sighash, child.privateKey);
          setKeyPair(map, concatBytes(typeKey(PSBT_IN_PARTIAL_SIG), pubkey), sig);
          break;
        }
        case "p2wpkh":
        case "p2sh-p2wpkh": {
          const pkh = hash160(pubkey);
          const expectedScript =
            spendType === "p2wpkh"
              ? concatBytes(new Uint8Array([0x00, 0x14]), pkh)
              : concatBytes(new Uint8Array([0xa9, 0x14]), hash160(concatBytes(new Uint8Array([0x00, 0x14]), pkh)), new Uint8Array([0x87]));
          if (!bytesEqual(prevout.scriptPubKey, expectedScript)) {
            throw new Error(`input ${i}: prevout script does not match the signing key`);
          }
          const sighash = segwitV0Sighash(psbt.tx, i, p2pkhScriptCode(pkh), prevout.value, SIGHASH_ALL);
          const sig = ecdsaSignChecked(sighash, child.privateKey);
          setKeyPair(map, concatBytes(typeKey(PSBT_IN_PARTIAL_SIG), pubkey), sig);
          break;
        }
        case "p2tr": {
          const internal = xOnly(pubkey);
          const declaredInternal = findOne(map, typeKey(PSBT_IN_TAP_INTERNAL_KEY));
          if (declaredInternal && !bytesEqual(declaredInternal, internal)) {
            throw new Error(`input ${i}: tap_internal_key does not match derived key`);
          }
          const tweaked = taprootTweakPrivateKey(child.privateKey);
          try {
            const outputKey = schnorr.getPublicKey(tweaked);
            const expectedScript = concatBytes(new Uint8Array([0x51, 0x20]), outputKey);
            if (!bytesEqual(prevout.scriptPubKey, expectedScript)) {
              throw new Error(`input ${i}: prevout script does not match the signing key`);
            }
            const allPrevouts: TxOutput[] = [];
            for (let j = 0; j < psbt.tx.inputs.length; j++) {
              const p = resolvePrevout(psbt, j);
              if (!p) throw new Error("taproot signing requires every input's utxo");
              allPrevouts.push(p);
            }
            const sighash = taprootSighash(psbt.tx, i, allPrevouts, SIGHASH_DEFAULT);
            const sig = schnorrSignChecked(sighash, tweaked);
            setKeyPair(map, typeKey(PSBT_IN_TAP_KEY_SIG), sig);
          } finally {
            zeroize(tweaked);
          }
          break;
        }
      }
      signedInputs.push(i);
    } finally {
      child.wipe();
    }
  }
  return { signedInputs, fee };
}

// --- finalize / extract ------------------------------------------------------

function serializeWitnessStack(items: Uint8Array[]): Uint8Array {
  const w = new ByteWriter();
  w.varInt(items.length);
  for (const item of items) w.varBytes(item);
  return w.finish();
}

function parseWitnessStack(raw: Uint8Array): Uint8Array[] {
  const r = new ByteReader(raw);
  const count = r.varInt();
  if (count > 1_000n) throw new Error("implausible witness item count");
  const items: Uint8Array[] = [];
  for (let i = 0n; i < count; i++) items.push(r.varBytes());
  if (!r.isDone()) throw new Error("trailing bytes in witness stack");
  return items;
}

/** Minimal script push (only lengths < 0x4c needed for sig/pubkey/redeem). */
function scriptPush(data: Uint8Array): Uint8Array {
  if (data.length === 0 || data.length >= 0x4c) throw new Error("unsupported push length");
  return concatBytes(new Uint8Array([data.length]), data);
}

function assertValidEcdsaSignature(sig: Uint8Array, pubkey: Uint8Array, sighash: Uint8Array): void {
  const hashByte = sig[sig.length - 1];
  if (hashByte !== SIGHASH_ALL) throw new Error("partial signature is not SIGHASH_ALL");
  const der = sig.slice(0, -1);
  if (!secp256k1.verify(der, sighash, pubkey, { lowS: true, format: "der" })) {
    throw new Error("partial signature does not verify — refusing to finalize");
  }
}

/**
 * Finalize all inputs. Every partial signature is verified against the
 * recomputed sighash before being committed — a finalizer must never emit a
 * transaction it has not checked.
 */
export function finalizePsbt(psbt: Psbt): void {
  for (let i = 0; i < psbt.tx.inputs.length; i++) {
    const map = psbt.inputMaps[i]!;
    if (findOne(map, typeKey(PSBT_IN_FINAL_SCRIPTSIG)) || findOne(map, typeKey(PSBT_IN_FINAL_SCRIPTWITNESS))) {
      // A pre-finalized input would bypass every verification below —
      // refuse rather than emit scripts this finalizer has not checked.
      throw new Error(`input ${i} is already finalized — refusing to pass through unverified scripts`);
    }
    const { spendType, prevout, redeemScript } = classifyInput(psbt, i);

    if (spendType === "p2tr") {
      const sig = findOne(map, typeKey(PSBT_IN_TAP_KEY_SIG));
      if (!sig) throw new Error(`input ${i} is missing its signature`);
      if (sig.length !== 64 && sig.length !== 65) throw new Error("malformed taproot signature");
      if (sig.length === 65 && sig[64] !== SIGHASH_ALL) throw new Error("taproot signature has unsupported sighash");
      const allPrevouts: TxOutput[] = [];
      for (let j = 0; j < psbt.tx.inputs.length; j++) {
        const p = resolvePrevout(psbt, j);
        if (!p) throw new Error("taproot finalize requires every input's utxo");
        allPrevouts.push(p);
      }
      const sighash = taprootSighash(psbt.tx, i, allPrevouts, sig.length === 65 ? SIGHASH_ALL : SIGHASH_DEFAULT);
      if (!schnorr.verify(sig.slice(0, 64), sighash, prevout.scriptPubKey.slice(2))) {
        throw new Error("taproot signature does not verify — refusing to finalize");
      }
      setKeyPair(map, typeKey(PSBT_IN_FINAL_SCRIPTWITNESS), serializeWitnessStack([sig]));
    } else {
      const partials = findByType(map, PSBT_IN_PARTIAL_SIG);
      if (partials.length === 0) throw new Error(`input ${i} is missing its signature`);
      if (partials.length > 1) throw new Error(`input ${i}: multiple partial signatures (multisig unsupported)`);
      const pubkey = partials[0]!.key.slice(1);
      if (pubkey.length !== 33) throw new Error("partial signature pubkey must be 33 bytes");
      const sig = partials[0]!.value;
      const pkh = hash160(pubkey);

      // The signature must come from the key the prevout actually pays —
      // otherwise a stray partial_sig would finalize into an unspendable
      // (or wrong-key) script.
      const expectedPkh =
        spendType === "p2pkh"
          ? prevout.scriptPubKey.slice(3, 23)
          : spendType === "p2wpkh"
            ? prevout.scriptPubKey.slice(2, 22)
            : redeemScript!.slice(2, 22);
      if (!bytesEqual(pkh, expectedPkh)) {
        throw new Error(`input ${i}: partial signature pubkey does not match the prevout`);
      }

      if (spendType === "p2pkh") {
        assertValidEcdsaSignature(sig, pubkey, legacySighash(psbt.tx, i, prevout.scriptPubKey, SIGHASH_ALL));
        setKeyPair(map, typeKey(PSBT_IN_FINAL_SCRIPTSIG), concatBytes(scriptPush(sig), scriptPush(pubkey)));
      } else if (spendType === "p2wpkh") {
        assertValidEcdsaSignature(sig, pubkey, segwitV0Sighash(psbt.tx, i, p2pkhScriptCode(pkh), prevout.value, SIGHASH_ALL));
        setKeyPair(map, typeKey(PSBT_IN_FINAL_SCRIPTWITNESS), serializeWitnessStack([sig, pubkey]));
      } else {
        if (!redeemScript) throw new Error("missing redeem script");
        assertValidEcdsaSignature(sig, pubkey, segwitV0Sighash(psbt.tx, i, p2pkhScriptCode(pkh), prevout.value, SIGHASH_ALL));
        setKeyPair(map, typeKey(PSBT_IN_FINAL_SCRIPTSIG), scriptPush(redeemScript));
        setKeyPair(map, typeKey(PSBT_IN_FINAL_SCRIPTWITNESS), serializeWitnessStack([sig, pubkey]));
      }
    }

    // Per BIP174, the finalizer removes the fields the final script replaces.
    removeType(map, PSBT_IN_PARTIAL_SIG);
    removeType(map, PSBT_IN_SIGHASH_TYPE);
    removeType(map, PSBT_IN_REDEEM_SCRIPT);
    removeType(map, PSBT_IN_BIP32_DERIVATION);
    removeType(map, PSBT_IN_TAP_KEY_SIG);
    removeType(map, PSBT_IN_TAP_BIP32_DERIVATION);
    removeType(map, PSBT_IN_TAP_INTERNAL_KEY);
  }
}

/** Extract the fully-signed network transaction. Throws if any input is not finalized. */
export function extractTx(psbt: Psbt): Transaction {
  const tx: Transaction = {
    version: psbt.tx.version,
    locktime: psbt.tx.locktime,
    inputs: psbt.tx.inputs.map((input) => ({ ...input, scriptSig: new Uint8Array(0), witness: [] })),
    outputs: psbt.tx.outputs.map((output) => ({ ...output })),
  };
  for (let i = 0; i < tx.inputs.length; i++) {
    const map = psbt.inputMaps[i]!;
    const scriptSig = findOne(map, typeKey(PSBT_IN_FINAL_SCRIPTSIG));
    const witness = findOne(map, typeKey(PSBT_IN_FINAL_SCRIPTWITNESS));
    if (!scriptSig && !witness) throw new Error(`input ${i} is not finalized`);
    if (scriptSig) tx.inputs[i]!.scriptSig = scriptSig;
    if (witness) tx.inputs[i]!.witness = parseWitnessStack(witness);
  }
  return tx;
}
