/**
 * Encrypted vault storage: Argon2id (memory-hard KDF, RFC 9106) from the
 * audited @noble/hashes, and AES-256-GCM from the platform WebCrypto
 * implementation. No hand-rolled cryptography.
 *
 * Format (versioned, self-describing):
 *   [0]      version = 0x01
 *   [1]      Argon2id time cost t
 *   [2]      Argon2id memory cost as log2(KiB)   (16 = 64 MiB)
 *   [3]      Argon2id parallelism p
 *   [4..19]  salt (16 bytes, CSPRNG)
 *   [20..31] AES-GCM IV (12 bytes, CSPRNG)
 *   [32..]   ciphertext || 16-byte GCM tag
 *
 * The header bytes [0..31] are bound as GCM additional authenticated data,
 * so an attacker cannot silently downgrade the KDF parameters.
 *
 * Security decisions:
 * - Argon2id defaults follow RFC 9106's second recommended option
 *   (t=3, m=64 MiB, p=1 fits browser/mobile memory budgets).
 * - A fresh salt and IV are drawn from the CSPRNG for every encryption; the
 *   IV is never reused under the same derived key because the key itself is
 *   salted per encryption.
 * - Decryption failure is a single opaque error: wrong password and corrupted
 *   data are indistinguishable to a caller (and an attacker).
 * - The derived key copy is zeroized immediately after WebCrypto import.
 */

import { argon2id } from "@noble/hashes/argon2";
import { concatBytes, zeroize } from "../util/bytes.js";

const VERSION = 0x01;
const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const HEADER_LENGTH = 4 + SALT_LENGTH + IV_LENGTH;

export interface KdfParams {
  timeCost: number;
  memoryLog2KiB: number;
  parallelism: number;
}

export const DEFAULT_KDF_PARAMS: KdfParams = {
  timeCost: 3,
  memoryLog2KiB: 16, // 2^16 KiB = 64 MiB
  parallelism: 1,
};

/** Bounds accepted at decryption time — rejects downgrade/DoS parameter abuse. */
const KDF_BOUNDS = {
  timeCost: { min: 1, max: 16 },
  memoryLog2KiB: { min: 13, max: 21 }, // 8 MiB .. 2 GiB
  parallelism: { min: 1, max: 4 },
};

function deriveKey(password: string, salt: Uint8Array, params: KdfParams): Uint8Array {
  const passwordBytes = new TextEncoder().encode(password.normalize("NFKD"));
  try {
    return argon2id(passwordBytes, salt, {
      t: params.timeCost,
      m: 2 ** params.memoryLog2KiB,
      p: params.parallelism,
      dkLen: 32,
    });
  } finally {
    zeroize(passwordBytes);
  }
}

async function importAesKey(rawKey: Uint8Array, usage: KeyUsage): Promise<CryptoKey> {
  return globalThis.crypto.subtle.importKey("raw", rawKey as BufferSource, { name: "AES-GCM" }, false, [usage]);
}

export async function encryptVault(
  plaintext: Uint8Array,
  password: string,
  params: KdfParams = DEFAULT_KDF_PARAMS,
): Promise<Uint8Array> {
  assertKdfParams(params);
  if (password.length === 0) throw new Error("password must not be empty");
  const salt = new Uint8Array(SALT_LENGTH);
  const iv = new Uint8Array(IV_LENGTH);
  globalThis.crypto.getRandomValues(salt);
  globalThis.crypto.getRandomValues(iv);

  const header = concatBytes(
    new Uint8Array([VERSION, params.timeCost, params.memoryLog2KiB, params.parallelism]),
    salt,
    iv,
  );

  const rawKey = deriveKey(password, salt, params);
  try {
    const key = await importAesKey(rawKey, "encrypt");
    const ciphertext = new Uint8Array(
      await globalThis.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv as BufferSource, additionalData: header as BufferSource },
        key,
        plaintext as BufferSource,
      ),
    );
    return concatBytes(header, ciphertext);
  } finally {
    zeroize(rawKey);
  }
}

export async function decryptVault(vault: Uint8Array, password: string): Promise<Uint8Array> {
  if (vault.length < HEADER_LENGTH + 16) throw new Error("vault data too short");
  if (vault[0] !== VERSION) throw new Error("unsupported vault version");
  const params: KdfParams = {
    timeCost: vault[1]!,
    memoryLog2KiB: vault[2]!,
    parallelism: vault[3]!,
  };
  assertKdfParams(params);
  const header = vault.slice(0, HEADER_LENGTH);
  const salt = vault.slice(4, 4 + SALT_LENGTH);
  const iv = vault.slice(4 + SALT_LENGTH, HEADER_LENGTH);
  const ciphertext = vault.slice(HEADER_LENGTH);

  const rawKey = deriveKey(password, salt, params);
  try {
    const key = await importAesKey(rawKey, "decrypt");
    const plaintext = await globalThis.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv as BufferSource, additionalData: header as BufferSource },
      key,
      ciphertext as BufferSource,
    );
    return new Uint8Array(plaintext);
  } catch {
    // Deliberately opaque: do not reveal whether the password or the data was bad.
    throw new Error("unable to decrypt vault");
  } finally {
    zeroize(rawKey);
  }
}

function assertKdfParams(params: KdfParams): void {
  const { timeCost, memoryLog2KiB, parallelism } = params;
  if (
    !Number.isInteger(timeCost) ||
    timeCost < KDF_BOUNDS.timeCost.min ||
    timeCost > KDF_BOUNDS.timeCost.max ||
    !Number.isInteger(memoryLog2KiB) ||
    memoryLog2KiB < KDF_BOUNDS.memoryLog2KiB.min ||
    memoryLog2KiB > KDF_BOUNDS.memoryLog2KiB.max ||
    !Number.isInteger(parallelism) ||
    parallelism < KDF_BOUNDS.parallelism.min ||
    parallelism > KDF_BOUNDS.parallelism.max
  ) {
    throw new Error("KDF parameters out of accepted bounds");
  }
}
