/**
 * Bitcoin hash primitives, composed exclusively from audited @noble/hashes.
 * No hash function is implemented in this codebase.
 */

import { sha256 } from "@noble/hashes/sha2";
import { ripemd160 } from "@noble/hashes/legacy";
import { concatBytes } from "../util/bytes.js";

/** SHA256(SHA256(x)) — txids, block hashes, base58check checksums. */
export function sha256d(data: Uint8Array): Uint8Array {
  return sha256(sha256(data));
}

/** RIPEMD160(SHA256(x)) — P2PKH/P2WPKH pubkey hashes, P2SH script hashes. */
export function hash160(data: Uint8Array): Uint8Array {
  return ripemd160(sha256(data));
}

const tagHashCache = new Map<string, Uint8Array>();

/** BIP340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg). */
export function taggedHash(tag: string, ...msgs: Uint8Array[]): Uint8Array {
  let tagHash = tagHashCache.get(tag);
  if (!tagHash) {
    tagHash = sha256(new TextEncoder().encode(tag));
    tagHashCache.set(tag, tagHash);
  }
  return sha256(concatBytes(tagHash, tagHash, ...msgs));
}
