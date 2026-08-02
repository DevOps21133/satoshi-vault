/**
 * BIP39 mnemonic implementation, written from scratch against the spec:
 * https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
 *
 * Verified against the official Trezor test vectors (see test/bip39.test.ts).
 *
 * Security decisions:
 * - Entropy is NEVER generated here. The caller must obtain it from the
 *   entropy engine (multi-source pool); this module only encodes/decodes.
 * - All intermediate buffers containing entropy or seeds are zeroized by the
 *   caller via the returned references; helper `mnemonicToSeed` copies are
 *   the caller's responsibility to wipe.
 * - Strings are NFKD-normalized per spec so passphrases match across platforms.
 */

import { sha256 } from "@noble/hashes/sha2";
import { pbkdf2 } from "@noble/hashes/pbkdf2";
import { sha512 } from "@noble/hashes/sha2";
import { WORDLIST_EN } from "./wordlist-en.js";

export const VALID_ENTROPY_BITS = [128, 160, 192, 224, 256] as const;
export type EntropyBits = (typeof VALID_ENTROPY_BITS)[number];

const wordIndex = new Map<string, number>(WORDLIST_EN.map((w, i) => [w, i]));

/** entropy (16/20/24/28/32 bytes) -> mnemonic words. */
export function entropyToMnemonic(entropy: Uint8Array): string[] {
  const bits = entropy.length * 8;
  if (!(VALID_ENTROPY_BITS as readonly number[]).includes(bits)) {
    throw new Error(`entropy must be one of ${VALID_ENTROPY_BITS.join("/")} bits, got ${bits}`);
  }
  const checksumBits = bits / 32;
  const hash = sha256(entropy);

  // Build the bit string: entropy || first (bits/32) bits of sha256(entropy).
  const totalBits = bits + checksumBits;
  const words: string[] = [];
  for (let w = 0; w < totalBits / 11; w++) {
    let idx = 0;
    for (let b = 0; b < 11; b++) {
      const bitPos = w * 11 + b;
      const source = bitPos < bits ? entropy : hash;
      const sourceBit = bitPos < bits ? bitPos : bitPos - bits;
      const bit = (source[sourceBit >> 3]! >> (7 - (sourceBit & 7))) & 1;
      idx = (idx << 1) | bit;
    }
    words.push(WORDLIST_EN[idx]!);
  }
  return words;
}

export interface MnemonicValidation {
  ok: boolean;
  error?: "word-count" | "unknown-word" | "checksum";
  unknownWords?: string[];
}

/** Validate word count, wordlist membership, and checksum. */
export function validateMnemonic(words: string[]): MnemonicValidation {
  const normalized = words.map((w) => w.normalize("NFKD").toLowerCase().trim());
  if (![12, 15, 18, 21, 24].includes(normalized.length)) {
    return { ok: false, error: "word-count" };
  }
  const unknown = normalized.filter((w) => !wordIndex.has(w));
  if (unknown.length > 0) {
    return { ok: false, error: "unknown-word", unknownWords: unknown };
  }
  try {
    const entropy = mnemonicToEntropy(normalized);
    entropy.fill(0);
  } catch {
    return { ok: false, error: "checksum" };
  }
  return { ok: true };
}

/** mnemonic -> original entropy; throws on invalid checksum. Caller must zeroize the result. */
export function mnemonicToEntropy(words: string[]): Uint8Array {
  const normalized = words.map((w) => w.normalize("NFKD").toLowerCase().trim());
  if (![12, 15, 18, 21, 24].includes(normalized.length)) {
    throw new Error("invalid word count");
  }
  // totalBits = entropyBits + entropyBits/32  =>  entropyBits = totalBits * 32 / 33
  const totalBits = normalized.length * 11;
  const entropyBits = (totalBits * 32) / 33;
  const checksumBits = totalBits - entropyBits;
  if (!Number.isInteger(entropyBits)) throw new Error("invalid word count");

  const allBits = new Uint8Array(totalBits);
  normalized.forEach((word, w) => {
    const idx = wordIndex.get(word);
    if (idx === undefined) throw new Error(`unknown word: ${word}`);
    for (let b = 0; b < 11; b++) {
      allBits[w * 11 + b] = (idx >> (10 - b)) & 1;
    }
  });

  const entropy = new Uint8Array(entropyBits / 8);
  for (let i = 0; i < entropyBits; i++) {
    if (allBits[i]) entropy[i >> 3] = entropy[i >> 3]! | (1 << (7 - (i & 7)));
  }

  const hash = sha256(entropy);
  for (let i = 0; i < checksumBits; i++) {
    const expected = (hash[i >> 3]! >> (7 - (i & 7))) & 1;
    if (allBits[entropyBits + i] !== expected) {
      entropy.fill(0);
      throw new Error("invalid mnemonic checksum");
    }
  }
  allBits.fill(0);
  return entropy;
}

/**
 * mnemonic (+ optional passphrase) -> 64-byte BIP39 seed.
 * PBKDF2-HMAC-SHA512, 2048 iterations, salt "mnemonic" + passphrase (NFKD).
 * Caller must zeroize the returned seed after deriving the HD master key.
 */
export function mnemonicToSeed(words: string[], passphrase = ""): Uint8Array {
  const sentence = words
    .map((w) => w.normalize("NFKD").toLowerCase().trim())
    .join(" ");
  const salt = ("mnemonic" + passphrase).normalize("NFKD");
  const encoder = new TextEncoder();
  const password = encoder.encode(sentence);
  const saltBytes = encoder.encode(salt);
  try {
    return pbkdf2(sha512, password, saltBytes, { c: 2048, dkLen: 64 });
  } finally {
    password.fill(0);
    saltBytes.fill(0);
  }
}
