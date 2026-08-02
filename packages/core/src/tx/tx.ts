/**
 * Bitcoin transaction model and wire serialization (BIP144 segwit format).
 * Implemented from the Bitcoin protocol documentation; txids verified against
 * known mainnet transactions and BIP143/BIP341 test vectors.
 */

import { sha256d } from "../crypto/hash.js";
import { ByteReader, ByteWriter } from "../util/writer.js";
import { bytesToHex, hexToBytes, reversed } from "../util/bytes.js";

export const SEQUENCE_FINAL = 0xffffffff;
/** Opt-in RBF (BIP125): any sequence < 0xfffffffe. This is our default. */
export const SEQUENCE_RBF = 0xfffffffd;

export interface TxInput {
  /** Previous txid in INTERNAL byte order (little-endian wire order). */
  prevTxid: Uint8Array;
  prevVout: number;
  scriptSig: Uint8Array;
  sequence: number;
  witness: Uint8Array[];
}

export interface TxOutput {
  /** Satoshis. bigint — never floating point for money. */
  value: bigint;
  scriptPubKey: Uint8Array;
}

export interface Transaction {
  version: number;
  inputs: TxInput[];
  outputs: TxOutput[];
  locktime: number;
}

export const MAX_MONEY = 21_000_000n * 100_000_000n;

/** Display txid (reversed hex) -> internal byte order. */
export function txidToBytes(displayHex: string): Uint8Array {
  if (!/^[0-9a-fA-F]{64}$/.test(displayHex)) throw new Error("txid must be 64 hex chars");
  return reversed(hexToBytes(displayHex));
}

/** Internal byte order -> display txid. */
export function txidToHex(internal: Uint8Array): string {
  if (internal.length !== 32) throw new Error("txid must be 32 bytes");
  return bytesToHex(reversed(internal));
}

export function assertSaneOutput(out: TxOutput): void {
  if (out.value < 0n || out.value > MAX_MONEY) throw new Error("output value out of range");
  if (out.scriptPubKey.length === 0 || out.scriptPubKey.length > 10_000) {
    throw new Error("invalid scriptPubKey length");
  }
}

function serializeInputsOutputs(w: ByteWriter, tx: Transaction): void {
  w.varInt(tx.inputs.length);
  for (const input of tx.inputs) {
    if (input.prevTxid.length !== 32) throw new Error("prevTxid must be 32 bytes");
    w.bytes(input.prevTxid).u32le(input.prevVout).varBytes(input.scriptSig).u32le(input.sequence);
  }
  w.varInt(tx.outputs.length);
  for (const output of tx.outputs) {
    assertSaneOutput(output);
    w.u64le(output.value).varBytes(output.scriptPubKey);
  }
}

export function hasWitness(tx: Transaction): boolean {
  return tx.inputs.some((i) => i.witness.length > 0);
}

/** Full serialization (with witness data when present). */
export function serializeTx(tx: Transaction): Uint8Array {
  const w = new ByteWriter();
  w.i32le(tx.version);
  const witness = hasWitness(tx);
  if (witness) w.u8(0x00).u8(0x01);
  serializeInputsOutputs(w, tx);
  if (witness) {
    for (const input of tx.inputs) {
      w.varInt(input.witness.length);
      for (const item of input.witness) w.varBytes(item);
    }
  }
  w.u32le(tx.locktime);
  return w.finish();
}

/** Legacy serialization (no witness) — this is what the txid commits to. */
export function serializeTxLegacy(tx: Transaction): Uint8Array {
  const w = new ByteWriter();
  w.i32le(tx.version);
  serializeInputsOutputs(w, tx);
  w.u32le(tx.locktime);
  return w.finish();
}

/** txid in display (reversed-hex) form. */
export function txid(tx: Transaction): string {
  return txidToHex(sha256d(serializeTxLegacy(tx)));
}

/** wtxid in display form. */
export function wtxid(tx: Transaction): string {
  return txidToHex(sha256d(serializeTx(tx)));
}

/** Parse a transaction; rejects trailing garbage and malformed data. */
export function parseTx(raw: Uint8Array): Transaction {
  const r = new ByteReader(raw);
  const version = r.i32le();

  let marker = false;
  let inputCount: bigint;
  const peek = r.varInt();
  if (peek === 0n) {
    // segwit marker; flag must be 0x01
    const flag = r.u8();
    if (flag !== 0x01) throw new Error("invalid segwit flag");
    marker = true;
    inputCount = r.varInt();
  } else {
    inputCount = peek;
  }
  if (inputCount > 100_000n) throw new Error("implausible input count");

  const inputs: TxInput[] = [];
  for (let i = 0n; i < inputCount; i++) {
    const prevTxid = r.bytes(32);
    const prevVout = r.u32le();
    const scriptSig = r.varBytes();
    const sequence = r.u32le();
    inputs.push({ prevTxid, prevVout, scriptSig, sequence, witness: [] });
  }

  const outputCount = r.varInt();
  if (outputCount > 100_000n) throw new Error("implausible output count");
  const outputs: TxOutput[] = [];
  for (let i = 0n; i < outputCount; i++) {
    const value = r.u64le();
    const scriptPubKey = r.varBytes();
    const out = { value, scriptPubKey };
    assertSaneOutput(out);
    outputs.push(out);
  }

  if (marker) {
    let anyWitness = false;
    for (const input of inputs) {
      const items = r.varInt();
      if (items > 1_000n) throw new Error("implausible witness item count");
      for (let j = 0n; j < items; j++) input.witness.push(r.varBytes());
      if (items > 0n) anyWitness = true;
    }
    if (!anyWitness) throw new Error("segwit marker present but no witness data");
  }

  const locktime = r.u32le();
  if (!r.isDone()) throw new Error("trailing bytes after transaction");
  return { version, inputs, outputs, locktime };
}
