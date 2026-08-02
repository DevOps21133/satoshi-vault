/**
 * Per-input signing for the four supported spend types.
 * ECDSA (RFC6979 deterministic nonce, low-S enforced) and BIP340 Schnorr come
 * from audited @noble/curves. This module only assembles scriptSig/witness.
 *
 * Every produced signature is immediately verified against the public key
 * before being accepted ("sign-then-verify"): this catches nonce/fault bugs
 * and glitched hardware before a broken signature leaks on-chain.
 */

import { secp256k1, schnorr } from "@noble/curves/secp256k1";
import { hash160 } from "../crypto/hash.js";
import { taprootTweakPrivateKey } from "../crypto/taproot.js";
import { bytesEqual, concatBytes, zeroize } from "../util/bytes.js";
import { ByteWriter } from "../util/writer.js";
import { Transaction, TxOutput } from "./tx.js";
import {
  legacySighash,
  segwitV0Sighash,
  taprootSighash,
  p2pkhScriptCode,
  SIGHASH_ALL,
  SIGHASH_DEFAULT,
} from "./sighash.js";

export type SpendType = "p2pkh" | "p2sh-p2wpkh" | "p2wpkh" | "p2tr";

export interface InputSigningInfo {
  spendType: SpendType;
  /** The UTXO being spent (script + amount). */
  prevout: TxOutput;
}

function randomAux(): Uint8Array {
  const aux = new Uint8Array(32);
  globalThis.crypto.getRandomValues(aux);
  return aux;
}

/** ECDSA sign with mandatory verify-after-sign. Returns DER || sighashByte. */
export function ecdsaSignChecked(msgHash: Uint8Array, privateKey: Uint8Array): Uint8Array {
  const sig = secp256k1.sign(msgHash, privateKey, { lowS: true });
  const pub = secp256k1.getPublicKey(privateKey, true);
  if (!secp256k1.verify(sig.toCompactRawBytes(), msgHash, pub, { lowS: true })) {
    throw new Error("self-verification of ECDSA signature failed");
  }
  return concatBytes(sig.toDERRawBytes(), new Uint8Array([SIGHASH_ALL]));
}

/** Schnorr sign (fresh CSPRNG aux randomness) with mandatory verify-after-sign. */
export function schnorrSignChecked(msgHash: Uint8Array, tweakedKey: Uint8Array): Uint8Array {
  const sig = schnorr.sign(msgHash, tweakedKey, randomAux());
  const pub = schnorr.getPublicKey(tweakedKey);
  if (!schnorr.verify(sig, msgHash, pub)) {
    throw new Error("self-verification of Schnorr signature failed");
  }
  return sig;
}

/**
 * Sign input `index` of `tx` in place.
 * `prevouts` must contain the spent output for EVERY input when any input is
 * taproot (BIP341 commits to all of them); for other types only
 * prevouts[index] is used.
 */
export function signInput(
  tx: Transaction,
  index: number,
  info: InputSigningInfo,
  privateKey: Uint8Array,
  allPrevouts?: TxOutput[],
): void {
  const input = tx.inputs[index];
  if (!input) throw new Error("input index out of range");
  const pubkey = secp256k1.getPublicKey(privateKey, true);
  const pkh = hash160(pubkey);
  const script = info.prevout.scriptPubKey;

  switch (info.spendType) {
    case "p2pkh": {
      // Guard: the prevout must actually pay our key.
      expectScript(script, concatBytes(new Uint8Array([0x76, 0xa9, 0x14]), pkh, new Uint8Array([0x88, 0xac])));
      const sighash = legacySighash(tx, index, script, SIGHASH_ALL);
      const sig = ecdsaSignChecked(sighash, privateKey);
      input.scriptSig = new ByteWriter().varBytes(sig).varBytes(pubkey).finish().slice(0);
      // varBytes writes length prefixes; scriptSig pushes are exactly that for <76 bytes.
      input.witness = [];
      break;
    }
    case "p2wpkh": {
      expectScript(script, concatBytes(new Uint8Array([0x00, 0x14]), pkh));
      const sighash = segwitV0Sighash(tx, index, p2pkhScriptCode(pkh), info.prevout.value, SIGHASH_ALL);
      const sig = ecdsaSignChecked(sighash, privateKey);
      input.scriptSig = new Uint8Array(0);
      input.witness = [sig, pubkey];
      break;
    }
    case "p2sh-p2wpkh": {
      const redeem = concatBytes(new Uint8Array([0x00, 0x14]), pkh);
      expectScript(script, concatBytes(new Uint8Array([0xa9, 0x14]), hash160(redeem), new Uint8Array([0x87])));
      const sighash = segwitV0Sighash(tx, index, p2pkhScriptCode(pkh), info.prevout.value, SIGHASH_ALL);
      const sig = ecdsaSignChecked(sighash, privateKey);
      // scriptSig = single push of the redeem script.
      input.scriptSig = new ByteWriter().varBytes(redeem).finish();
      input.witness = [sig, pubkey];
      break;
    }
    case "p2tr": {
      if (!allPrevouts) throw new Error("taproot signing requires all prevouts");
      // The sighash commits to allPrevouts[index]; it must be the same UTXO
      // the caller validated as info.prevout, or the checks above are moot.
      const own = allPrevouts[index];
      if (!own || own.value !== info.prevout.value || !bytesEqual(own.scriptPubKey, info.prevout.scriptPubKey)) {
        throw new Error("allPrevouts[index] disagrees with info.prevout");
      }
      const tweaked = taprootTweakPrivateKey(privateKey);
      try {
        const outputKey = schnorr.getPublicKey(tweaked);
        expectScript(script, concatBytes(new Uint8Array([0x51, 0x20]), outputKey));
        const sighash = taprootSighash(tx, index, allPrevouts, SIGHASH_DEFAULT);
        const sig = schnorrSignChecked(sighash, tweaked);
        input.scriptSig = new Uint8Array(0);
        input.witness = [sig]; // SIGHASH_DEFAULT: no hashtype byte
      } finally {
        zeroize(tweaked);
      }
      break;
    }
  }
}

function expectScript(actual: Uint8Array, expected: Uint8Array): void {
  if (actual.length !== expected.length || !actual.every((b, i) => b === expected[i])) {
    throw new Error("prevout script does not match the signing key — refusing to sign");
  }
}
