/**
 * Wallet persistence: watch-only accounts (PUBLIC keys only), Esplora
 * endpoint overrides, and the address book. Nothing here is secret — the
 * Wallet app never holds private key material at all.
 */

import { AccountExport, accountExportFromJson, NetworkName, NETWORKS } from "@satoshivault/core";

const ACCOUNTS_KEY = "satoshivault.wallet.accounts";
const ESPLORA_KEY_PREFIX = "satoshivault.wallet.esplora.";
const BOOK_KEY = "satoshivault.wallet.addressbook";

export interface StoredAccount {
  id: string;
  label: string;
  data: AccountExport;
}

export function accountId(data: AccountExport): string {
  return `${data.masterFingerprint}:${data.path}:${data.network}`;
}

export function loadAccounts(): StoredAccount[] {
  const raw = localStorage.getItem(ACCOUNTS_KEY);
  if (!raw) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return [];
  }
  if (!Array.isArray(parsed)) return [];
  const out: StoredAccount[] = [];
  for (const entry of parsed) {
    if (typeof entry !== "object" || entry === null) continue;
    const o = entry as Record<string, unknown>;
    if (typeof o["id"] !== "string" || typeof o["label"] !== "string") continue;
    try {
      // Re-validate through the hostile-input parser on every load.
      const data = accountExportFromJson(new TextEncoder().encode(JSON.stringify(o["data"])));
      out.push({ id: o["id"], label: o["label"], data });
    } catch {
      continue;
    }
  }
  return out;
}

function saveAccounts(list: StoredAccount[]): void {
  localStorage.setItem(ACCOUNTS_KEY, JSON.stringify(list));
}

export function addAccount(label: string, data: AccountExport): StoredAccount {
  const list = loadAccounts();
  const id = accountId(data);
  if (list.some((a) => a.id === id)) throw new Error("this account is already imported");
  const account: StoredAccount = { id, label: label.slice(0, 60) || "Account", data };
  list.push(account);
  saveAccounts(list);
  return account;
}

export function renameAccount(id: string, label: string): void {
  const list = loadAccounts();
  const account = list.find((a) => a.id === id);
  if (!account) return;
  account.label = label.slice(0, 60) || account.label;
  saveAccounts(list);
}

export function removeAccount(id: string): void {
  saveAccounts(loadAccounts().filter((a) => a.id !== id));
}

// --- esplora endpoints -------------------------------------------------------

export const DEFAULT_ESPLORA: Record<NetworkName, string> = {
  mainnet: "https://blockstream.info/api",
  testnet: "https://blockstream.info/testnet/api",
  signet: "https://mempool.space/signet/api",
  regtest: "http://127.0.0.1:3002",
};

export function esploraUrl(network: NetworkName): string {
  return localStorage.getItem(ESPLORA_KEY_PREFIX + network) ?? DEFAULT_ESPLORA[network];
}

export function setEsploraUrl(network: NetworkName, url: string): void {
  const trimmed = url.trim();
  if (trimmed === "") {
    localStorage.removeItem(ESPLORA_KEY_PREFIX + network);
    return;
  }
  const parsed = new URL(trimmed); // throws on garbage
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new Error("endpoint must be http(s)");
  }
  localStorage.setItem(ESPLORA_KEY_PREFIX + network, trimmed.replace(/\/+$/, ""));
}

export function networkNames(): NetworkName[] {
  return Object.keys(NETWORKS) as NetworkName[];
}

// --- address book ------------------------------------------------------------

export interface BookEntry {
  label: string;
  address: string;
  network: string;
}

export function loadBook(): BookEntry[] {
  const raw = localStorage.getItem(BOOK_KEY);
  if (!raw) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return [];
  }
  if (!Array.isArray(parsed)) return [];
  return parsed.filter(
    (e): e is BookEntry =>
      typeof e === "object" && e !== null &&
      typeof (e as Record<string, unknown>)["label"] === "string" &&
      typeof (e as Record<string, unknown>)["address"] === "string" &&
      typeof (e as Record<string, unknown>)["network"] === "string",
  );
}

export function saveBook(entries: BookEntry[]): void {
  localStorage.setItem(BOOK_KEY, JSON.stringify(entries));
}

export function addBookEntry(entry: BookEntry): void {
  const list = loadBook();
  if (list.some((e) => e.address === entry.address && e.network === entry.network)) {
    throw new Error("address already in the book");
  }
  list.push({ ...entry, label: entry.label.slice(0, 60) || "Unnamed" });
  saveBook(list);
}

export function removeBookEntry(address: string, network: string): void {
  saveBook(loadBook().filter((e) => !(e.address === address && e.network === network)));
}
