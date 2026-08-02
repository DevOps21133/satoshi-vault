/**
 * Signature hashes for all supported spend types:
 *  - Legacy (pre-segwit) P2PKH
 *  - BIP143 witness v0 (P2WPKH and P2SH-P2WPKH)
 *  - BIP341 witness v1 (taproot key path, SIGHASH_DEFAULT)
 *
 * SECURITY DECISION: only SIGHASH_ALL (0x01) and SIGHASH_DEFAULT (0x00,
 * taproot) are supported. NONE/SINGLE/ANYONECANPAY variants allow an attacker
 * who obtains a signature to redirect funds and are not needed for a
 * single-sig wallet, so requests for them are rejected outright.
 * Verified against the official BIP143 example vectors and the BIP341
 * wallet-test-vectors.json.
 */

import { sha256 } from "@noble/hashes/sha2";
import { sha256d, taggedHash } from "../crypto/hash.js";
import { ByteWriter } from "../util/writer.js";
import { concatBytes } from "../util/bytes.js";
import { Transaction, TxOutput } from "./tx.js";

export const SIGHASH_DEFAULT = 0x00;
export const SIGHASH_ALL = 0x01;

function assertSupportedSighash(type: number, taproot: boolean): void {
  if (taproot ? type !== SIGHASH_DEFAULT && type !== SIGHASH_ALL : type !== SIGHASH_ALL) {
    throw new Error(`unsupported sighash type 0x${type.toString(16)}: only SIGHASH_ALL/DEFAULT are allowed`);
  }
}

/** Legacy sighash (P2PKH). scriptCode = prevout scriptPubKey. */
export function legacySighash(
  tx: Transaction,
  inputIndex: number,
  scriptCode: Uint8Array,
  sighashType: number = SIGHASH_ALL,
): Uint8Array {
  assertSupportedSighash(sighashType, false);
  if (inputIndex < 0 || inputIndex >= tx.inputs.length) throw new Error("input index out of range");
  const w = new ByteWriter();
  w.i32le(tx.version);
  w.varInt(tx.inputs.length);
  tx.inputs.forEach((input, i) => {
    w.bytes(input.prevTxid)
      .u32le(input.prevVout)
      .varBytes(i === inputIndex ? scriptCode : new Uint8Array(0))
      .u32le(input.sequence);
  });
  w.varInt(tx.outputs.length);
  for (const out of tx.outputs) w.u64le(out.value).varBytes(out.scriptPubKey);
  w.u32le(tx.locktime);
  w.u32le(sighashType);
  return sha256d(w.finish());
}

/** BIP143 sighash for witness v0. scriptCode: P2WPKH = 1976a914{pkh}88ac. */
export function segwitV0Sighash(
  tx: Transaction,
  inputIndex: number,
  scriptCode: Uint8Array,
  value: bigint,
  sighashType: number = SIGHASH_ALL,
): Uint8Array {
  assertSupportedSighash(sighashType, false);
  const input = tx.inputs[inputIndex];
  if (!input) throw new Error("input index out of range");

  const prevouts = new ByteWriter();
  for (const i of tx.inputs) prevouts.bytes(i.prevTxid).u32le(i.prevVout);
  const hashPrevouts = sha256d(prevouts.finish());

  const sequences = new ByteWriter();
  for (const i of tx.inputs) sequences.u32le(i.sequence);
  const hashSequence = sha256d(sequences.finish());

  const outputs = new ByteWriter();
  for (const o of tx.outputs) outputs.u64le(o.value).varBytes(o.scriptPubKey);
  const hashOutputs = sha256d(outputs.finish());

  const w = new ByteWriter();
  w.i32le(tx.version)
    .bytes(hashPrevouts)
    .bytes(hashSequence)
    .bytes(input.prevTxid)
    .u32le(input.prevVout)
    .varBytes(scriptCode)
    .u64le(value)
    .u32le(input.sequence)
    .bytes(hashOutputs)
    .u32le(tx.locktime)
    .u32le(sighashType);
  return sha256d(w.finish());
}

/**
 * BIP341 taproot key-path sighash (SIGHASH_DEFAULT).
 * Requires the scriptPubKey and amount of EVERY input's prevout.
 */
export function taprootSighash(
  tx: Transaction,
  inputIndex: number,
  prevouts: TxOutput[],
  sighashType: number = SIGHASH_DEFAULT,
): Uint8Array {
  assertSupportedSighash(sighashType, true);
  if (prevouts.length !== tx.inputs.length) {
    throw new Error("taproot sighash requires all input prevouts");
  }
  if (inputIndex < 0 || inputIndex >= tx.inputs.length) throw new Error("input index out of range");

  const prevoutsW = new ByteWriter();
  const amountsW = new ByteWriter();
  const scriptsW = new ByteWriter();
  const sequencesW = new ByteWriter();
  tx.inputs.forEach((input, i) => {
    prevoutsW.bytes(input.prevTxid).u32le(input.prevVout);
    amountsW.u64le(prevouts[i]!.value);
    scriptsW.varBytes(prevouts[i]!.scriptPubKey);
    sequencesW.u32le(input.sequence);
  });
  const outputsW = new ByteWriter();
  for (const o of tx.outputs) outputsW.u64le(o.value).varBytes(o.scriptPubKey);

  const w = new ByteWriter();
  w.u8(0x00); // sighash epoch
  w.u8(sighashType);
  w.i32le(tx.version);
  w.u32le(tx.locktime);
  w.bytes(sha256(prevoutsW.finish()));
  w.bytes(sha256(amountsW.finish()));
  w.bytes(sha256(scriptsW.finish()));
  w.bytes(sha256(sequencesW.finish()));
  if (sighashType === SIGHASH_DEFAULT || sighashType === SIGHASH_ALL) {
    w.bytes(sha256(outputsW.finish()));
  }
  w.u8(0x00); // spend_type: key path, no annex
  w.u32le(inputIndex);
  return taggedHash("TapSighash", w.finish());
}

/** scriptCode for P2WPKH/P2PKH signing: the canonical P2PKH script over the pubkey hash. */
export function p2pkhScriptCode(pubkeyHash: Uint8Array): Uint8Array {
  if (pubkeyHash.length !== 20) throw new Error("pubkey hash must be 20 bytes");
  return concatBytes(new Uint8Array([0x76, 0xa9, 0x14]), pubkeyHash, new Uint8Array([0x88, 0xac]));
}
