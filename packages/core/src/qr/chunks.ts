/**
 * Animated-QR chunk framing for the air-gap channel between the Signer and
 * the watch-only Wallet.
 *
 * Frame format (ASCII, QR byte mode):
 *   SV1:<TYPE>:<index>/<total>:<groupId>:<payload-base64url>
 *
 *   TYPE     PSBT | TXN | XPUB  (what the payload reassembles into)
 *   index    1-based frame number
 *   total    total frame count (constant across the group)
 *   groupId  first 16 hex chars (64 bits) of SHA-256 over
 *            "SV1:<TYPE>:<total>:" || payload — the id commits to the payload
 *            AND to the frame type/count, so frames cannot be re-labelled or
 *            re-split without changing the id, and the receiver rejects
 *            frames from a different transfer mixed into the stream
 *
 * After reassembly the full hash is recomputed and checked against the
 * groupId, so a corrupted or spliced transfer can never be accepted.
 * All frames are parsed as hostile input: strict grammar, bounded sizes,
 * consistency enforced across frames, total transfer size capped.
 */

import { sha256 } from "@noble/hashes/sha2";
import { base64urlnopad } from "@scure/base";
import { bytesToHex, concatBytes } from "../util/bytes.js";

export type ChunkPayloadType = "PSBT" | "TXN" | "XPUB";

const PREFIX = "SV1";
const MAX_FRAMES = 2000;
const MAX_FRAME_PAYLOAD = 1200; // bytes per frame before base64 (fits QR v22 @ EC-M)
/** Hard cap on a reassembled payload — bounds hostile-stream memory use. */
export const MAX_TRANSFER_BYTES = 1_000_000;
export const DEFAULT_FRAME_PAYLOAD = 300;

function groupIdFor(type: ChunkPayloadType, total: number, payload: Uint8Array): string {
  const header = new TextEncoder().encode(`${PREFIX}:${type}:${total}:`);
  return bytesToHex(sha256(concatBytes(header, payload))).slice(0, 16);
}

/** Split a payload into animated-QR frame strings. */
export function encodeChunks(
  type: ChunkPayloadType,
  payload: Uint8Array,
  bytesPerFrame: number = DEFAULT_FRAME_PAYLOAD,
): string[] {
  if (payload.length === 0) throw new Error("empty payload");
  if (payload.length > MAX_TRANSFER_BYTES) throw new Error("payload too large for QR transfer");
  if (!Number.isInteger(bytesPerFrame) || bytesPerFrame < 50 || bytesPerFrame > MAX_FRAME_PAYLOAD) {
    throw new Error("bytesPerFrame out of range");
  }
  const total = Math.ceil(payload.length / bytesPerFrame);
  if (total > MAX_FRAMES) throw new Error("payload too large for QR transfer");
  const groupId = groupIdFor(type, total, payload);
  const frames: string[] = [];
  for (let i = 0; i < total; i++) {
    const slice = payload.slice(i * bytesPerFrame, (i + 1) * bytesPerFrame);
    frames.push(`${PREFIX}:${type}:${i + 1}/${total}:${groupId}:${base64urlnopad.encode(slice)}`);
  }
  return frames;
}

export interface ParsedFrame {
  type: ChunkPayloadType;
  index: number; // 1-based
  total: number;
  groupId: string;
  payload: Uint8Array;
}

/**
 * A single frame failed to parse — typically a stray/foreign QR code in the
 * camera's view. Scanners may IGNORE this error class; every other error from
 * the assembler (conflicting payloads, inconsistent frames, size cap) is a
 * tampering signal and must be surfaced, never swallowed.
 */
export class FrameParseError extends Error {}

const FRAME_RE = /^SV1:(PSBT|TXN|XPUB):([0-9]{1,4})\/([0-9]{1,4}):([0-9a-f]{16}):([A-Za-z0-9_-]{1,1600})$/;

export function parseFrame(frame: string): ParsedFrame {
  if (frame.length > 4000) throw new FrameParseError("frame too long");
  const m = FRAME_RE.exec(frame.trim());
  if (!m) throw new FrameParseError("not a Satoshi Vault QR frame");
  const type = m[1] as ChunkPayloadType;
  const index = parseInt(m[2]!, 10);
  const total = parseInt(m[3]!, 10);
  if (total < 1 || total > MAX_FRAMES || index < 1 || index > total) {
    throw new FrameParseError("frame index out of range");
  }
  let payload: Uint8Array;
  try {
    payload = base64urlnopad.decode(m[5]!);
  } catch {
    throw new FrameParseError("frame payload is not valid base64url");
  }
  if (payload.length === 0 || payload.length > MAX_FRAME_PAYLOAD) {
    throw new FrameParseError("frame payload size out of range");
  }
  return { type, index, total, groupId: m[4]!, payload };
}

export interface AssemblyProgress {
  received: number;
  total: number;
  ratio: number;
  type: ChunkPayloadType;
  groupId: string;
}

/**
 * Reassembles frames scanned in any order. Frames from other groups are
 * ignored (returned progress is unchanged) so a camera pointed at a stale
 * animation cannot poison an in-flight transfer.
 */
export class ChunkAssembler {
  private frames = new Map<number, Uint8Array>();
  private type: ChunkPayloadType | null = null;
  private total = 0;
  private groupId: string | null = null;
  private receivedBytes = 0;

  /** Feed one scanned frame. Returns current progress. */
  add(frame: string): AssemblyProgress {
    const parsed = parseFrame(frame);
    if (this.groupId === null) {
      this.groupId = parsed.groupId;
      this.total = parsed.total;
      this.type = parsed.type;
    } else if (parsed.groupId !== this.groupId) {
      return this.progress(); // different transfer — ignore
    } else if (parsed.total !== this.total || parsed.type !== this.type) {
      throw new Error("inconsistent frames within one transfer");
    }
    const existing = this.frames.get(parsed.index);
    if (existing) {
      if (bytesToHex(existing) !== bytesToHex(parsed.payload)) {
        throw new Error("conflicting payloads for the same frame");
      }
    } else {
      this.receivedBytes += parsed.payload.length;
      if (this.receivedBytes > MAX_TRANSFER_BYTES) {
        this.reset();
        throw new Error("transfer exceeds maximum size");
      }
      this.frames.set(parsed.index, parsed.payload);
    }
    return this.progress();
  }

  progress(): AssemblyProgress {
    if (this.groupId === null || this.type === null) {
      return { received: 0, total: 0, ratio: 0, type: "PSBT", groupId: "" };
    }
    return {
      received: this.frames.size,
      total: this.total,
      ratio: this.total === 0 ? 0 : this.frames.size / this.total,
      type: this.type,
      groupId: this.groupId,
    };
  }

  isComplete(): boolean {
    return this.groupId !== null && this.frames.size === this.total;
  }

  /** Reassemble and verify the payload hash against the groupId. */
  assemble(): { type: ChunkPayloadType; payload: Uint8Array } {
    if (!this.isComplete() || this.type === null || this.groupId === null) {
      throw new Error("transfer incomplete");
    }
    let length = 0;
    for (let i = 1; i <= this.total; i++) {
      const frame = this.frames.get(i);
      if (!frame) throw new Error("transfer incomplete");
      length += frame.length;
    }
    const payload = new Uint8Array(length);
    let offset = 0;
    for (let i = 1; i <= this.total; i++) {
      const frame = this.frames.get(i)!;
      payload.set(frame, offset);
      offset += frame.length;
    }
    if (groupIdFor(this.type, this.total, payload) !== this.groupId) {
      throw new Error("payload hash mismatch — transfer corrupted");
    }
    return { type: this.type, payload };
  }

  reset(): void {
    this.frames.clear();
    this.type = null;
    this.total = 0;
    this.groupId = null;
    this.receivedBytes = 0;
  }
}
