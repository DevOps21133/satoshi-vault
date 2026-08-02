/**
 * Bitcoin address encoding/decoding for the four supported output types:
 *   P2PKH (legacy), P2SH (used here only as P2SH-P2WPKH), P2WPKH, P2TR.
 *
 * Every decode validates: checksum, length, witness version, network prefix.
 * Addresses are treated as hostile input (QR codes, clipboards, files).
 *
 * Encodings come from audited @scure/base (base58check, bech32, bech32m).
 */

import { sha256 } from "@noble/hashes/sha2";
import { createBase58check, bech32, bech32m } from "@scure/base";
import { hash160 } from "../crypto/hash.js";
import { taprootOutputKey, xOnly } from "../crypto/taproot.js";
import { concatBytes } from "../util/bytes.js";
import { Network } from "./network.js";

const base58check = createBase58check(sha256);

export type AddressType = "p2pkh" | "p2sh" | "p2wpkh" | "p2wsh" | "p2tr";

export interface DecodedAddress {
  type: AddressType;
  /** The scriptPubKey this address pays to. */
  scriptPubKey: Uint8Array;
  network: Network["name"] | "testnet-like";
}

// -- scriptPubKey builders ---------------------------------------------------

export function p2pkhScript(pubkeyHash: Uint8Array): Uint8Array {
  if (pubkeyHash.length !== 20) throw new Error("pubkey hash must be 20 bytes");
  return concatBytes(new Uint8Array([0x76, 0xa9, 0x14]), pubkeyHash, new Uint8Array([0x88, 0xac]));
}

export function p2shScript(scriptHash: Uint8Array): Uint8Array {
  if (scriptHash.length !== 20) throw new Error("script hash must be 20 bytes");
  return concatBytes(new Uint8Array([0xa9, 0x14]), scriptHash, new Uint8Array([0x87]));
}

export function p2wpkhScript(pubkeyHash: Uint8Array): Uint8Array {
  if (pubkeyHash.length !== 20) throw new Error("pubkey hash must be 20 bytes");
  return concatBytes(new Uint8Array([0x00, 0x14]), pubkeyHash);
}

export function p2wshScript(scriptHash32: Uint8Array): Uint8Array {
  if (scriptHash32.length !== 32) throw new Error("witness script hash must be 32 bytes");
  return concatBytes(new Uint8Array([0x00, 0x20]), scriptHash32);
}

export function p2trScript(outputKeyXOnly: Uint8Array): Uint8Array {
  if (outputKeyXOnly.length !== 32) throw new Error("taproot output key must be 32 bytes");
  return concatBytes(new Uint8Array([0x51, 0x20]), outputKeyXOnly);
}

/** Redeem script for P2SH-wrapped P2WPKH (BIP49). */
export function p2shP2wpkhRedeemScript(pubkey: Uint8Array): Uint8Array {
  return p2wpkhScript(hash160(pubkey));
}

// -- pubkey -> address -------------------------------------------------------

export function p2pkhAddress(pubkey: Uint8Array, network: Network): string {
  return base58check.encode(concatBytes(new Uint8Array([network.pubKeyHash]), hash160(pubkey)));
}

export function p2shP2wpkhAddress(pubkey: Uint8Array, network: Network): string {
  const redeem = p2shP2wpkhRedeemScript(pubkey);
  return base58check.encode(concatBytes(new Uint8Array([network.scriptHash]), hash160(redeem)));
}

export function p2wpkhAddress(pubkey: Uint8Array, network: Network): string {
  return bech32.encode(network.bech32, [0, ...bech32.toWords(hash160(pubkey))]);
}

/** BIP86: taproot address from the 33-byte compressed internal pubkey. */
export function p2trAddress(internalPubkey: Uint8Array, network: Network): string {
  const outputKey = taprootOutputKey(xOnly(internalPubkey));
  return bech32m.encode(network.bech32, [1, ...bech32m.toWords(outputKey)]);
}

// -- address -> script (validated decode) ------------------------------------

export function decodeAddress(address: string, network: Network): DecodedAddress {
  const trimmed = address.trim();
  if (trimmed.length === 0 || trimmed.length > 100) throw new Error("invalid address length");

  // bech32 / bech32m
  const lower = trimmed.toLowerCase();
  if (lower !== trimmed && trimmed.toUpperCase() !== trimmed) {
    // BIP173 forbids mixed case.
    if (lower.startsWith(network.bech32 + "1")) throw new Error("mixed-case bech32 address");
  }
  if (lower.startsWith(network.bech32 + "1")) {
    return decodeBech32(lower, network);
  }
  if (/^(bc|tb|bcrt)1/.test(lower)) {
    throw new Error(`address is for a different network (expected ${network.bech32}1…)`);
  }

  // base58
  let payload: Uint8Array;
  try {
    payload = base58check.decode(trimmed);
  } catch {
    throw new Error("invalid address: bad base58 checksum or encoding");
  }
  if (payload.length !== 21) throw new Error("invalid base58 address payload");
  const version = payload[0]!;
  const hash = payload.slice(1);
  if (version === network.pubKeyHash) {
    return { type: "p2pkh", scriptPubKey: p2pkhScript(hash), network: network.name };
  }
  if (version === network.scriptHash) {
    return { type: "p2sh", scriptPubKey: p2shScript(hash), network: network.name };
  }
  throw new Error("address version does not match the selected network");
}

function decodeBech32(lower: string, network: Network): DecodedAddress {
  // Try bech32 first (v0), then bech32m (v1+); reject wrong-variant checksums per BIP350.
  let words: number[];
  let variant: "bech32" | "bech32m";
  try {
    const dec = bech32.decode(lower as `${string}1${string}`, 90);
    if (dec.prefix !== network.bech32) throw new Error("wrong prefix");
    words = [...dec.words];
    variant = "bech32";
  } catch {
    const dec = bech32m.decode(lower as `${string}1${string}`, 90);
    if (dec.prefix !== network.bech32) {
      throw new Error("address prefix does not match the selected network");
    }
    words = [...dec.words];
    variant = "bech32m";
  }
  if (words.length === 0) throw new Error("empty witness program");
  const version = words[0]!;
  const program = bech32.fromWords(words.slice(1));
  if (version === 0) {
    if (variant !== "bech32") throw new Error("witness v0 must use bech32 checksum");
    if (program.length === 20) {
      return { type: "p2wpkh", scriptPubKey: p2wpkhScript(program), network: network.name };
    }
    if (program.length === 32) {
      return { type: "p2wsh", scriptPubKey: p2wshScript(program), network: network.name };
    }
    throw new Error("invalid witness v0 program length");
  }
  if (version === 1) {
    if (variant !== "bech32m") throw new Error("witness v1 must use bech32m checksum");
    if (program.length !== 32) throw new Error("invalid taproot program length");
    return { type: "p2tr", scriptPubKey: p2trScript(program), network: network.name };
  }
  throw new Error(`unsupported witness version ${version}`);
}

/** Best-effort scriptPubKey -> address (for transaction previews). */
export function scriptToAddress(script: Uint8Array, network: Network): string | null {
  try {
    if (script.length === 25 && script[0] === 0x76 && script[1] === 0xa9 && script[2] === 0x14 && script[23] === 0x88 && script[24] === 0xac) {
      return base58check.encode(concatBytes(new Uint8Array([network.pubKeyHash]), script.slice(3, 23)));
    }
    if (script.length === 23 && script[0] === 0xa9 && script[1] === 0x14 && script[22] === 0x87) {
      return base58check.encode(concatBytes(new Uint8Array([network.scriptHash]), script.slice(2, 22)));
    }
    if (script.length === 22 && script[0] === 0x00 && script[1] === 0x14) {
      return bech32.encode(network.bech32, [0, ...bech32.toWords(script.slice(2))]);
    }
    if (script.length === 34 && script[0] === 0x00 && script[1] === 0x20) {
      return bech32.encode(network.bech32, [0, ...bech32.toWords(script.slice(2))]);
    }
    if (script.length === 34 && script[0] === 0x51 && script[1] === 0x20) {
      return bech32m.encode(network.bech32, [1, ...bech32m.toWords(script.slice(2))]);
    }
    return null;
  } catch {
    return null;
  }
}
