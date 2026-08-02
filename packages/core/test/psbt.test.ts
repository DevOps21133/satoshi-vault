import { describe, it, expect } from "vitest";
import { mnemonicToSeed } from "../src/bip39/mnemonic.js";
import { HDPrivateKey, HARDENED_OFFSET } from "../src/bip32/hdkey.js";
import { MAINNET, TESTNET } from "../src/address/network.js";
import {
  p2pkhScript,
  p2shScript,
  p2wpkhScript,
  p2trScript,
  p2shP2wpkhRedeemScript,
} from "../src/address/address.js";
import { hash160, sha256d } from "../src/crypto/hash.js";
import { taprootOutputKey, xOnly } from "../src/crypto/taproot.js";
import { Transaction, serializeTx, serializeTxLegacy, parseTx, SEQUENCE_RBF } from "../src/tx/tx.js";
import {
  createPsbt,
  parsePsbt,
  serializePsbt,
  psbtToBase64,
  psbtFromBase64,
  psbtFee,
  signPsbt,
  finalizePsbt,
  extractTx,
  setWitnessUtxo,
  setNonWitnessUtxo,
  setRedeemScript,
  setBip32Derivation,
  setTapBip32Derivation,
  setTapInternalKey,
  setKeyPair,
  validateSigningPath,
  PSBT_IN_SIGHASH_TYPE,
} from "../src/psbt/psbt.js";
import { ByteWriter } from "../src/util/writer.js";
import { hexToBytes } from "../src/util/bytes.js";

const MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".split(" ");
const H = HARDENED_OFFSET;

function master(): HDPrivateKey {
  return HDPrivateKey.fromSeed(mnemonicToSeed(MNEMONIC));
}

interface Fixture {
  psbt: ReturnType<typeof createPsbt>;
  fundingTx: Transaction;
  masterKey: HDPrivateKey;
}

/** Funding tx pays all four script types at .../0/0; spend consumes all four. */
function buildFixture(): Fixture {
  const m = master();
  const fp = m.fingerprint;

  const keys = {
    p2pkh: m.derivePath("44'/0'/0'/0/0"),
    p2sh: m.derivePath("49'/0'/0'/0/0"),
    p2wpkh: m.derivePath("84'/0'/0'/0/0"),
    p2tr: m.derivePath("86'/0'/0'/0/0"),
  };

  const scripts = [
    p2pkhScript(hash160(keys.p2pkh.publicKey)),
    p2shScript(hash160(p2shP2wpkhRedeemScript(keys.p2sh.publicKey))),
    p2wpkhScript(hash160(keys.p2wpkh.publicKey)),
    p2trScript(taprootOutputKey(xOnly(keys.p2tr.publicKey))),
  ];

  const fundingTx: Transaction = {
    version: 2,
    locktime: 0,
    inputs: [
      {
        prevTxid: new Uint8Array(32).fill(7),
        prevVout: 0,
        scriptSig: new Uint8Array([0x51]),
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: scripts.map((scriptPubKey) => ({ value: 100_000n, scriptPubKey })),
  };
  const fundingTxid = sha256d(serializeTxLegacy(fundingTx));

  const recipient = m.derivePath("84'/0'/0'/0/5");
  const spendTx: Transaction = {
    version: 2,
    locktime: 0,
    inputs: scripts.map((_, vout) => ({
      prevTxid: fundingTxid,
      prevVout: vout,
      scriptSig: new Uint8Array(0),
      sequence: SEQUENCE_RBF,
      witness: [],
    })),
    outputs: [{ value: 350_000n, scriptPubKey: p2wpkhScript(hash160(recipient.publicKey)) }],
  };

  const psbt = createPsbt(spendTx);

  // input 0: p2pkh — legacy inputs carry the full previous transaction.
  setNonWitnessUtxo(psbt.inputMaps[0]!, serializeTx(fundingTx));
  setBip32Derivation(psbt.inputMaps[0]!, {
    pubkey: keys.p2pkh.publicKey,
    masterFingerprint: fp,
    path: [44 + H, 0 + H, 0 + H, 0, 0],
  });

  // input 1: p2sh-p2wpkh
  setWitnessUtxo(psbt.inputMaps[1]!, fundingTx.outputs[1]!);
  setRedeemScript(psbt.inputMaps[1]!, p2shP2wpkhRedeemScript(keys.p2sh.publicKey));
  setBip32Derivation(psbt.inputMaps[1]!, {
    pubkey: keys.p2sh.publicKey,
    masterFingerprint: fp,
    path: [49 + H, 0 + H, 0 + H, 0, 0],
  });

  // input 2: p2wpkh
  setWitnessUtxo(psbt.inputMaps[2]!, fundingTx.outputs[2]!);
  setBip32Derivation(psbt.inputMaps[2]!, {
    pubkey: keys.p2wpkh.publicKey,
    masterFingerprint: fp,
    path: [84 + H, 0 + H, 0 + H, 0, 0],
  });

  // input 3: p2tr
  setWitnessUtxo(psbt.inputMaps[3]!, fundingTx.outputs[3]!);
  setTapInternalKey(psbt.inputMaps[3]!, xOnly(keys.p2tr.publicKey));
  setTapBip32Derivation(psbt.inputMaps[3]!, {
    pubkey: xOnly(keys.p2tr.publicKey),
    masterFingerprint: fp,
    path: [86 + H, 0 + H, 0 + H, 0, 0],
  });

  for (const k of Object.values(keys)) k.wipe();
  return { psbt, fundingTx, masterKey: m };
}

describe("PSBT end-to-end (all four spend types)", () => {
  it("create -> serialize -> parse -> sign -> finalize -> extract", () => {
    const { psbt, masterKey } = buildFixture();

    // serialize/parse round trip before signing
    const reparsed = psbtFromBase64(psbtToBase64(psbt));
    expect(psbtFee(reparsed)).toBe(50_000n);

    const result = signPsbt(reparsed, masterKey, MAINNET);
    expect(result.signedInputs).toEqual([0, 1, 2, 3]);
    expect(result.fee).toBe(50_000n);

    // extraction must fail before finalization
    expect(() => extractTx(reparsed)).toThrow(/not finalized/);

    finalizePsbt(reparsed);
    const finalTx = extractTx(reparsed);

    // p2pkh input: scriptSig set, no witness; segwit inputs: witness set
    expect(finalTx.inputs[0]!.scriptSig.length).toBeGreaterThan(100);
    expect(finalTx.inputs[0]!.witness.length).toBe(0);
    expect(finalTx.inputs[1]!.witness.length).toBe(2);
    expect(finalTx.inputs[1]!.scriptSig.length).toBe(23); // push of redeem script
    expect(finalTx.inputs[2]!.witness.length).toBe(2);
    expect(finalTx.inputs[3]!.witness.length).toBe(1);
    expect(finalTx.inputs[3]!.witness[0]!.length).toBe(64); // schnorr, SIGHASH_DEFAULT

    // network serialization round-trips
    const raw = serializeTx(finalTx);
    expect(serializeTx(parseTx(raw))).toEqual(raw);
    masterKey.wipe();
  });

  it("signing is idempotent input-wise and PSBT stays combiner-compatible", () => {
    const { psbt, masterKey } = buildFixture();
    signPsbt(psbt, masterKey, MAINNET);
    const b64 = psbtToBase64(psbt);
    const again = psbtFromBase64(b64);
    finalizePsbt(again);
    expect(() => extractTx(again)).not.toThrow();
    masterKey.wipe();
  });
});

describe("PSBT signer refuses dangerous requests", () => {
  it("wrong network (path coin type mismatch)", () => {
    const { psbt, masterKey } = buildFixture();
    expect(() => signPsbt(psbt, masterKey, TESTNET)).toThrow(/coin type/);
    masterKey.wipe();
  });

  it("path steering: purpose does not match script type", () => {
    expect(() => validateSigningPath([84 + H, 0 + H, 0 + H, 0, 0], "p2pkh", MAINNET)).toThrow(/purpose/);
    expect(() => validateSigningPath([44 + H, 0 + H, 0 + H, 0, 0], "p2pkh", MAINNET)).not.toThrow();
    expect(() => validateSigningPath([44 + H, 0 + H, 0 + H, 2, 0], "p2pkh", MAINNET)).toThrow(/change/);
    expect(() => validateSigningPath([44 + H, 0 + H, 0, 0, 0], "p2pkh", MAINNET)).toThrow(/hardened/);
    expect(() => validateSigningPath([44 + H, 0 + H, 0 + H, 0, 5 + H], "p2pkh", MAINNET)).toThrow(/non-hardened/);
  });

  it("forbidden sighash type declared in the PSBT", () => {
    const { psbt, masterKey } = buildFixture();
    const single = new ByteWriter().u32le(0x03).finish();
    setKeyPair(psbt.inputMaps[2]!, new Uint8Array([PSBT_IN_SIGHASH_TYPE]), single);
    expect(() => signPsbt(psbt, masterKey, MAINNET)).toThrow(/refusing sighash/);
    masterKey.wipe();
  });

  it("non_witness_utxo txid mismatch (amount-forgery defense)", () => {
    const { psbt, fundingTx } = buildFixture();
    const forged: Transaction = { ...fundingTx, locktime: 999 };
    setNonWitnessUtxo(psbt.inputMaps[0]!, serializeTx(forged));
    expect(() => psbtFee(psbt)).toThrow(/txid does not match/);
  });

  it("witness_utxo disagreeing with non_witness_utxo", () => {
    const { psbt, fundingTx } = buildFixture();
    setWitnessUtxo(psbt.inputMaps[0]!, { value: 999_999n, scriptPubKey: fundingTx.outputs[0]!.scriptPubKey });
    expect(() => psbtFee(psbt)).toThrow(/disagrees/);
  });

  it("tampered amount after signing fails finalization", () => {
    const { psbt, fundingTx, masterKey } = buildFixture();
    signPsbt(psbt, masterKey, MAINNET);
    setWitnessUtxo(psbt.inputMaps[2]!, {
      value: 5n, // lie about the amount the signature committed to
      scriptPubKey: fundingTx.outputs[2]!.scriptPubKey,
    });
    expect(() => finalizePsbt(psbt)).toThrow(/does not verify/);
    masterKey.wipe();
  });

  it("negative fee (outputs exceed inputs)", () => {
    const { psbt } = buildFixture();
    psbt.tx.outputs[0]!.value = 500_000n;
    expect(() => psbtFee(psbt)).toThrow(/negative fee/);
  });
});

describe("PSBT parser rejects malformed data", () => {
  it("bad magic", () => {
    expect(() => psbtFromBase64("cHNiZAA=")).toThrow(/magic/);
  });

  it("trailing bytes", () => {
    const { psbt } = buildFixture();
    const raw = serializePsbt(psbt);
    const extended = new Uint8Array(raw.length + 1);
    extended.set(raw);
    expect(() => parsePsbt(extended)).toThrow();
  });

  it("duplicate keys in a map", () => {
    const { psbt } = buildFixture();
    const raw = serializePsbt(psbt);
    // craft: magic + global map with the unsigned-tx key twice
    const txValue = serializeTxLegacy(psbt.tx);
    const w = new ByteWriter();
    w.bytes(hexToBytes("70736274ff"));
    w.varBytes(new Uint8Array([0x00])).varBytes(txValue);
    w.varBytes(new Uint8Array([0x00])).varBytes(txValue);
    w.u8(0x00);
    expect(() => parsePsbt(w.finish())).toThrow(/duplicate/);
    expect(raw.length).toBeGreaterThan(0);
  });

  it("unsigned tx with a scriptSig is rejected", () => {
    const { psbt } = buildFixture();
    psbt.tx.inputs[0]!.scriptSig = new Uint8Array([0x51]);
    const raw = serializePsbt(psbt);
    expect(() => parsePsbt(raw)).toThrow(/empty scriptSigs/);
  });
});
