/**
 * Byte utilities.
 *
 * Security notes:
 * - `zeroize` overwrites secret material in place. JavaScript cannot guarantee
 *   that no copy exists elsewhere (GC, engine internals), but wiping every
 *   buffer we control shrinks the window in which a memory dump is useful.
 * - `constantTimeEqual` avoids early-exit comparison for secret-dependent data.
 */

export function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i]!.toString(16).padStart(2, "0");
  }
  return out;
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("hex string must have even length");
  if (!/^[0-9a-fA-F]*$/.test(hex)) throw new Error("invalid hex characters");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/** Constant-time comparison for secret-dependent data (MACs, checksums of secrets). */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/** Overwrite secret bytes. Call on every buffer holding key material once done. */
export function zeroize(...buffers: (Uint8Array | undefined)[]): void {
  for (const b of buffers) {
    if (b) b.fill(0);
  }
}

/** Big-endian 32-bit unsigned integer to 4 bytes. */
export function u32be(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) throw new Error("u32 out of range");
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, false);
  return out;
}

/** Reverse a copy (Bitcoin displays txids as reversed hashes). */
export function reversed(bytes: Uint8Array): Uint8Array {
  const out = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) out[i] = bytes[bytes.length - 1 - i]!;
  return out;
}
