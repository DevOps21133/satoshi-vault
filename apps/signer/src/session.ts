/**
 * An unlocked session: the BIP32 master key held in memory only.
 *
 * Lifecycle: unlock() decrypts the vault, derives the seed (with the BIP39
 * passphrase if one is used), builds the master node, and zeroizes the seed.
 * lock() wipes the master key material. The mnemonic words are JS strings and
 * cannot be reliably zeroized — a documented platform limitation; they are
 * dropped as soon as the master key exists.
 */

import {
  decryptVault,
  HDPrivateKey,
  mnemonicToSeed,
  validateMnemonic,
  zeroize,
} from "@satoshivault/core";

export interface Session {
  master: HDPrivateKey;
  /** Hex master fingerprint, e.g. "73c5da0a". */
  fingerprint: string;
}

export interface VaultPayload {
  version: 1;
  words: string[];
}

export function encodeVaultPayload(words: string[]): Uint8Array {
  const payload: VaultPayload = { version: 1, words };
  return new TextEncoder().encode(JSON.stringify(payload));
}

function decodeVaultPayload(raw: Uint8Array): string[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(raw));
  } catch {
    throw new Error("vault payload is corrupted");
  }
  if (typeof parsed !== "object" || parsed === null) throw new Error("vault payload is corrupted");
  const o = parsed as Record<string, unknown>;
  if (o["version"] !== 1 || !Array.isArray(o["words"]) || !o["words"].every((w) => typeof w === "string")) {
    throw new Error("vault payload is corrupted");
  }
  return o["words"] as string[];
}

export function sessionFromWords(words: string[], passphrase: string): Session {
  const check = validateMnemonic(words);
  if (!check.ok) throw new Error(check.error ?? "invalid mnemonic");
  const seed = mnemonicToSeed(words, passphrase);
  try {
    const master = HDPrivateKey.fromSeed(seed);
    return { master, fingerprint: master.fingerprint.toString(16).padStart(8, "0") };
  } finally {
    zeroize(seed);
  }
}

export async function unlock(blob: Uint8Array, password: string, passphrase: string): Promise<Session> {
  const plaintext = await decryptVault(blob, password);
  try {
    const words = decodeVaultPayload(plaintext);
    return sessionFromWords(words, passphrase);
  } finally {
    zeroize(plaintext);
  }
}

/** Decrypt just the mnemonic (for the guarded "reveal backup" flow). */
export async function revealWords(blob: Uint8Array, password: string): Promise<string[]> {
  const plaintext = await decryptVault(blob, password);
  try {
    return decodeVaultPayload(plaintext);
  } finally {
    zeroize(plaintext);
  }
}

export function lock(session: Session): void {
  session.master.wipe();
}
