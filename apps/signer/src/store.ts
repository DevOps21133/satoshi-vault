/**
 * Signer persistence. The ONLY secret ever written to disk is the encrypted
 * vault blob (Argon2id + AES-256-GCM, produced by @satoshivault/core). All
 * other keys are non-secret preferences.
 */

import { bytesToHex, hexToBytes, NetworkName, NETWORKS } from "@satoshivault/core";

const VAULT_KEY = "satoshivault.signer.vault";
const NETWORK_KEY = "satoshivault.signer.network";
const PASSPHRASE_FLAG_KEY = "satoshivault.signer.uses-passphrase";

export function saveVaultBlob(blob: Uint8Array): void {
  localStorage.setItem(VAULT_KEY, bytesToHex(blob));
}

export function loadVaultBlob(): Uint8Array | null {
  const hex = localStorage.getItem(VAULT_KEY);
  if (!hex) return null;
  try {
    return hexToBytes(hex);
  } catch {
    return null;
  }
}

export function hasVault(): boolean {
  return localStorage.getItem(VAULT_KEY) !== null;
}

/** Destroys the encrypted vault. Irreversible without the mnemonic backup. */
export function wipeVault(): void {
  localStorage.removeItem(VAULT_KEY);
  localStorage.removeItem(PASSPHRASE_FLAG_KEY);
}

export function saveNetworkName(name: NetworkName): void {
  localStorage.setItem(NETWORK_KEY, name);
}

export function loadNetworkName(): NetworkName {
  const raw = localStorage.getItem(NETWORK_KEY);
  return raw && raw in NETWORKS ? (raw as NetworkName) : "mainnet";
}

/**
 * Non-secret UX hint: whether this vault was created with a BIP39 passphrase,
 * so the unlock screen knows to show the passphrase field. The passphrase
 * itself is NEVER stored — it exists only in memory during a session.
 */
export function setUsesPassphrase(flag: boolean): void {
  if (flag) localStorage.setItem(PASSPHRASE_FLAG_KEY, "1");
  else localStorage.removeItem(PASSPHRASE_FLAG_KEY);
}

export function usesPassphrase(): boolean {
  return localStorage.getItem(PASSPHRASE_FLAG_KEY) === "1";
}
