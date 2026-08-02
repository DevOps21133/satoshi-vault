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

  // input 1: p2sh-p2wpkh — non_witness_utxo required for all non-taproot
  // inputs (amount forgery defense); witness_utxo kept for compatibility.
  setNonWitnessUtxo(psbt.inputMaps[1]!, serializeTx(fundingTx));
  setWitnessUtxo(psbt.inputMaps[1]!, fundingTx.outputs[1]!);
  setRedeemScript(psbt.inputMaps[1]!, p2shP2wpkhRedeemScript(keys.p2sh.publicKey));
  setBip32Derivation(psbt.inputMaps[1]!, {
    pubkey: keys.p2sh.publicKey,
    masterFingerprint: fp,
    path: [49 + H, 0 + H, 0 + H, 0, 0],
  });

  // input 2: p2wpkh
  setNonWitnessUtxo(psbt.inputMaps[2]!, serializeTx(fundingTx));
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

  it("witness_utxo lie next to the full tx is caught immediately", () => {
    const { psbt, fundingTx, masterKey } = buildFixture();
    signPsbt(psbt, masterKey, MAINNET);
    setWitnessUtxo(psbt.inputMaps[2]!, {
      value: 5n, // lie about the amount the signature committed to
      scriptPubKey: fundingTx.outputs[2]!.scriptPubKey,
    });
    expect(() => finalizePsbt(psbt)).toThrow(/disagrees/);
    masterKey.wipe();
  });

  it("tampered taproot amount after signing fails finalization", () => {
    const { psbt, fundingTx, masterKey } = buildFixture();
    signPsbt(psbt, masterKey, MAINNET);
    setWitnessUtxo(psbt.inputMaps[3]!, {
      value: 5n, // taproot has no non_witness_utxo; the BIP341 sighash catches it
      scriptPubKey: fundingTx.outputs[3]!.scriptPubKey,
    });
    expect(() => finalizePsbt(psbt)).toThrow(/does not verify/);
    masterKey.wipe();
  });

  it("segwit v0 input with only witness_utxo is refused (amount forgery defense)", () => {
    const { psbt, masterKey } = buildFixture();
    const map = psbt.inputMaps[2]!;
    for (let i = map.length - 1; i >= 0; i--) {
      if (map[i]!.key[0] === 0x00 && map[i]!.key.length === 1) map.splice(i, 1);
    }
    expect(() => signPsbt(psbt, masterKey, MAINNET)).toThrow(/requires non_witness_utxo/);
    masterKey.wipe();
  });

  it("implausible address index is refused", () => {
    expect(() => validateSigningPath([44 + H, 0 + H, 0 + H, 0, 5_000_000], "p2pkh", MAINNET)).toThrow(
      /implausible address index/,
    );
  });

  it("a forged derivation entry with a colliding fingerprint cannot block signing", () => {
    const { psbt, masterKey } = buildFixture();
    const map = psbt.inputMaps[2]!;
    // The attacker writes the PSBT, so they choose the byte ORDER too: the
    // forged entry goes FIRST. It claims our (public) fingerprint, carries a
    // key we cannot reproduce, and declares a path that violates the wallet
    // policy (44' purpose on a p2wpkh input). Signing must skip it and sign
    // every legitimate input — appending it instead would make this test pass
    // without ever exercising the hostile ordering.
    setBip32Derivation(map, {
      pubkey: new Uint8Array(33).fill(2),
      masterFingerprint: masterKey.fingerprint,
      path: [44 + H, 0 + H, 0 + H, 0, 1],
    });
    map.unshift(map.pop()!);
    const result = signPsbt(psbt, masterKey, MAINNET);
    expect(result.signedInputs).toEqual([0, 1, 2, 3]);
    masterKey.wipe();
  });

  it("a malformed derivation entry only costs its own input", () => {
    const { psbt, masterKey } = buildFixture();
    // A 7-byte value cannot be (fingerprint || path). Parsing it throws, and
    // that throw must not take down the signing of the other three inputs.
    const key = new Uint8Array(34);
    key[0] = 0x06; // PSBT_IN_BIP32_DERIVATION
    key.set(new Uint8Array(33).fill(4), 1);
    setKeyPair(psbt.inputMaps[2]!, key, new Uint8Array(7));
    const result = signPsbt(psbt, masterKey, MAINNET);
    expect(result.signedInputs).toEqual([0, 1, 3]);
    masterKey.wipe();
  });

  it("a policy-violating path for a key that IS ours is still fatal", () => {
    const { psbt, masterKey } = buildFixture();
    const map = psbt.inputMaps[2]!;
    // A key that genuinely IS ours (m/44'/0'/0'/0/0 reproduces this pubkey)
    // pointed at a p2wpkh input. Unlike a forgery we cannot reproduce, this one
    // survives the pubkey check, so the only thing standing between the vault
    // and signing off-policy is validateSigningPath — and it must throw rather
    // than sign. The entry goes FIRST so it is reached before the legitimate
    // 84' entry short-circuits the loop.
    const legacyKey = masterKey.derivePath("44'/0'/0'/0/0");
    setBip32Derivation(map, {
      pubkey: legacyKey.publicKey,
      masterFingerprint: masterKey.fingerprint,
      path: [44 + H, 0 + H, 0 + H, 0, 0],
    });
    map.unshift(map.pop()!);
    legacyKey.wipe();
    expect(() => signPsbt(psbt, masterKey, MAINNET)).toThrow(/purpose/);
    masterKey.wipe();
  });

  it("a PSBT spending the same outpoint twice is rejected at parse", () => {
    const { psbt } = buildFixture();
    // Duplicate outpoint: psbtFee would count the same prevout value twice and
    // show the human a plausible fee for a transaction that can never confirm.
    psbt.tx.inputs[1] = { ...psbt.tx.inputs[0]! };
    expect(() => parsePsbt(serializePsbt(psbt))).toThrow(/same outpoint twice/);
  });

  it("pre-finalized inputs are refused by the finalizer", () => {
    const { psbt, masterKey } = buildFixture();
    signPsbt(psbt, masterKey, MAINNET);
    setKeyPair(psbt.inputMaps[2]!, new Uint8Array([0x08]), new Uint8Array([0x00])); // FINAL_SCRIPTWITNESS
    expect(() => finalizePsbt(psbt)).toThrow(/already finalized/);
    masterKey.wipe();
  });

  it("a partial signature from a foreign key cannot be finalized", () => {
    const { psbt, masterKey } = buildFixture();
    signPsbt(psbt, masterKey, MAINNET);
    const map = psbt.inputMaps[2]!;
    for (const kp of map) {
      if (kp.key[0] === 0x02 && kp.key.length === 34) {
        // Re-attribute the signature to a different pubkey.
        const forgedKey = kp.key.slice();
        forgedKey.set(new Uint8Array(33).fill(3), 1);
        kp.key = forgedKey;
      }
    }
    expect(() => finalizePsbt(psbt)).toThrow(/does not match the prevout/);
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
