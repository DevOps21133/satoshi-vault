/**
 * Watch-only accounts: what the Signer exports (over QR) and the Wallet
 * imports. An account is a single-sig BIP44/49/84/86 account-level xpub plus
 * the metadata a watch-only wallet needs to derive addresses and to build
 * PSBTs the signer will accept (master fingerprint + derivation path).
 *
 * The export payload is JSON with strict validation on import — it arrives
 * over the QR channel and is treated as hostile.
 */

import { HDPublicKey, HDPrivateKey, VERSIONS, parseExtendedKey, parsePath, HARDENED_OFFSET } from "../bip32/hdkey.js";
import { Network, MAINNET, NETWORKS } from "../address/network.js";
import { p2pkhAddress, p2shP2wpkhAddress, p2wpkhAddress, p2trAddress } from "../address/address.js";
import { SpendType } from "../tx/sign.js";
import { bytesToHex } from "../util/bytes.js";
import { hash160 } from "../crypto/hash.js";

export const PURPOSE_BY_SPEND_TYPE: Record<SpendType, number> = {
  p2pkh: 44,
  "p2sh-p2wpkh": 49,
  p2wpkh: 84,
  p2tr: 86,
};

export const SPEND_TYPE_BY_PURPOSE: Record<number, SpendType> = {
  44: "p2pkh",
  49: "p2sh-p2wpkh",
  84: "p2wpkh",
  86: "p2tr",
};

/** SLIP-132 version bytes for each account type (mainnet / test networks). */
function versionsFor(spendType: SpendType, network: Network): { private: number; public: number } {
  const testnet = network.name !== MAINNET.name;
  switch (spendType) {
    case "p2sh-p2wpkh":
      return testnet ? VERSIONS.uprv : VERSIONS.yprv;
    case "p2wpkh":
      return testnet ? VERSIONS.vprv : VERSIONS.zprv;
    default:
      // BIP44 legacy and BIP86 taproot both use xpub/tpub.
      return testnet ? VERSIONS.tprv : VERSIONS.xprv;
  }
}

export interface AccountExport {
  version: 1;
  /** Hex master fingerprint (8 chars). */
  masterFingerprint: string;
  network: string;
  scriptType: SpendType;
  /** Account path, e.g. "m/84'/0'/0'". */
  path: string;
  xpub: string;
}

/** Derive the account node and produce the export payload (Signer side). */
export function exportAccount(
  master: HDPrivateKey,
  spendType: SpendType,
  network: Network,
  accountIndex = 0,
): AccountExport {
  if (!Number.isInteger(accountIndex) || accountIndex < 0 || accountIndex > 100_000) {
    throw new Error("implausible account index");
  }
  const purpose = PURPOSE_BY_SPEND_TYPE[spendType];
  const coin = network.name === MAINNET.name ? 0 : 1;
  const path = `m/${purpose}'/${coin}'/${accountIndex}'`;
  const account = master.derivePath(path.slice(2));
  try {
    return {
      version: 1,
      masterFingerprint: bytesToHex(hash160(master.publicKey).slice(0, 4)),
      network: network.name,
      scriptType: spendType,
      path,
      xpub: account.neutered().toExtended(versionsFor(spendType, network).public),
    };
  } finally {
    account.wipe();
  }
}

export class WatchAccount {
  readonly node: HDPublicKey;
  readonly network: Network;
  readonly scriptType: SpendType;
  readonly masterFingerprint: number;
  readonly accountPath: number[];

  constructor(data: AccountExport) {
    // --- strict validation of the hostile import payload ---
    if (data.version !== 1) throw new Error("unsupported account export version");
    const network = (NETWORKS as Record<string, Network>)[data.network];
    if (!network) throw new Error("unknown network");
    if (!(data.scriptType in PURPOSE_BY_SPEND_TYPE)) throw new Error("unknown script type");
    if (!/^[0-9a-f]{8}$/.test(data.masterFingerprint)) throw new Error("malformed master fingerprint");

    const path = parsePath(data.path);
    if (path.length !== 3) throw new Error("account path must have 3 levels");
    const [purpose, coin, account] = path as [number, number, number];
    if (purpose !== PURPOSE_BY_SPEND_TYPE[data.scriptType] + HARDENED_OFFSET) {
      throw new Error("path purpose does not match script type");
    }
    if (coin !== (network.name === MAINNET.name ? 0 : 1) + HARDENED_OFFSET) {
      throw new Error("path coin type does not match network");
    }
    if (account < HARDENED_OFFSET) throw new Error("account level must be hardened");

    const parsed = parseExtendedKey(data.xpub);
    if (parsed.isPrivate) throw new Error("refusing to import private key material into the watch wallet");
    const expected = versionsFor(data.scriptType, network).public;
    if (parsed.version !== expected) throw new Error("xpub version does not match script type/network");
    const node = parsed.key as HDPublicKey;
    if (node.meta.depth !== 3) throw new Error("xpub must be an account-level key (depth 3)");
    if (node.meta.childIndex !== account) throw new Error("xpub child index does not match path");

    this.node = node;
    this.network = network;
    this.scriptType = data.scriptType;
    this.masterFingerprint = parseInt(data.masterFingerprint, 16);
    this.accountPath = path;
  }

  /** Non-hardened derivation of a receive (change=0) or change (change=1) key. */
  publicKeyAt(change: 0 | 1, index: number): Uint8Array {
    if (!Number.isInteger(index) || index < 0 || index >= HARDENED_OFFSET) {
      throw new Error("invalid address index");
    }
    return this.node.deriveChild(change).deriveChild(index).publicKey;
  }

  addressAt(change: 0 | 1, index: number): string {
    const pubkey = this.publicKeyAt(change, index);
    switch (this.scriptType) {
      case "p2pkh":
        return p2pkhAddress(pubkey, this.network);
      case "p2sh-p2wpkh":
        return p2shP2wpkhAddress(pubkey, this.network);
      case "p2wpkh":
        return p2wpkhAddress(pubkey, this.network);
      case "p2tr":
        return p2trAddress(pubkey, this.network);
    }
  }

  /** Full path for input/output derivation fields in PSBTs. */
  fullPath(change: 0 | 1, index: number): number[] {
    return [...this.accountPath, change, index];
  }
}

export function accountExportToJson(data: AccountExport): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(data));
}

export function accountExportFromJson(raw: Uint8Array): AccountExport {
  if (raw.length > 4096) throw new Error("account export too large");
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(raw));
  } catch {
    throw new Error("account export is not valid JSON");
  }
  if (typeof parsed !== "object" || parsed === null) throw new Error("malformed account export");
  const o = parsed as Record<string, unknown>;
  if (
    o["version"] !== 1 ||
    typeof o["masterFingerprint"] !== "string" ||
    typeof o["network"] !== "string" ||
    typeof o["scriptType"] !== "string" ||
    typeof o["path"] !== "string" ||
    typeof o["xpub"] !== "string"
  ) {
    throw new Error("malformed account export");
  }
  // Full semantic validation happens in the WatchAccount constructor.
  return {
    version: 1,
    masterFingerprint: o["masterFingerprint"],
    network: o["network"],
    scriptType: o["scriptType"] as SpendType,
    path: o["path"],
    xpub: o["xpub"],
  };
}
