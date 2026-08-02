/**
 * BIP32 hierarchical deterministic keys, implemented from the spec:
 * https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 *
 * Verified against all five official BIP32 test vectors (test/bip32.test.ts).
 *
 * Elliptic-curve operations come exclusively from the audited @noble/curves
 * secp256k1 implementation — this file only performs the BIP32 scalar
 * addition (IL + k) mod n and point addition via library calls, never raw
 * field math.
 *
 * Security decisions:
 * - Private keys live in Uint8Arrays owned by HDPrivateKey; call .wipe()
 *   when a branch is no longer needed.
 * - Hardened derivation is required for account-level paths (enforced in
 *   paths.ts) so a leaked xpub + child private key cannot compromise the
 *   parent (the classic BIP32 pitfall).
 */

import { hmac } from "@noble/hashes/hmac";
import { sha512, sha256 } from "@noble/hashes/sha2";
import { secp256k1 } from "@noble/curves/secp256k1";
import { createBase58check } from "@scure/base";
import { concatBytes, u32be, zeroize } from "../util/bytes.js";
import { hash160 } from "../crypto/hash.js";

const base58check = createBase58check(sha256);
const CURVE_N = secp256k1.CURVE.n;

export const HARDENED_OFFSET = 0x80000000;

/** SLIP-132 / BIP32 serialization version bytes. */
export interface Bip32Versions {
  private: number;
  public: number;
}
export const VERSIONS = {
  // mainnet
  xprv: { private: 0x0488ade4, public: 0x0488b21e },
  yprv: { private: 0x049d7878, public: 0x049d7cb2 }, // SLIP-132 p2sh-p2wpkh
  zprv: { private: 0x04b2430c, public: 0x04b24746 }, // SLIP-132 p2wpkh
  // testnet/signet/regtest
  tprv: { private: 0x04358394, public: 0x043587cf },
  uprv: { private: 0x044a4e28, public: 0x044a5262 },
  vprv: { private: 0x045f18bc, public: 0x045f1cf6 },
} as const satisfies Record<string, Bip32Versions>;

function bytesToBigInt(b: Uint8Array): bigint {
  let n = 0n;
  for (const byte of b) n = (n << 8n) | BigInt(byte);
  return n;
}

function bigIntTo32(n: bigint): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

function assertValidPrivateKey(k: bigint): void {
  if (k === 0n || k >= CURVE_N) throw new Error("derived key outside curve order (retry next index)");
}

export interface HDNodeMeta {
  depth: number;
  parentFingerprint: number;
  childIndex: number;
}

export class HDPublicKey {
  constructor(
    /** 33-byte compressed SEC1 public key. */
    public readonly publicKey: Uint8Array,
    public readonly chainCode: Uint8Array,
    public readonly meta: HDNodeMeta,
  ) {
    if (publicKey.length !== 33) throw new Error("public key must be 33 bytes");
    if (chainCode.length !== 32) throw new Error("chain code must be 32 bytes");
    // Throws if the point is not on the curve — rejects malicious xpubs.
    secp256k1.ProjectivePoint.fromHex(publicKey);
  }

  get fingerprint(): number {
    const h = hash160(this.publicKey);
    return new DataView(h.buffer, h.byteOffset, 4).getUint32(0, false);
  }

  /** CKDpub — non-hardened public child derivation (watch-only wallets). */
  deriveChild(index: number): HDPublicKey {
    if (!Number.isInteger(index) || index < 0 || index >= HARDENED_OFFSET) {
      throw new Error("public derivation only supports non-hardened indices");
    }
    const data = concatBytes(this.publicKey, u32be(index));
    const I = hmac(sha512, this.chainCode, data);
    const IL = I.slice(0, 32);
    const IR = I.slice(32);
    const ilScalar = bytesToBigInt(IL);
    if (ilScalar >= CURVE_N) throw new Error("derived key outside curve order (retry next index)");
    const parent = secp256k1.ProjectivePoint.fromHex(this.publicKey);
    const child = secp256k1.ProjectivePoint.BASE.multiply(ilScalar).add(parent);
    if (child.equals(secp256k1.ProjectivePoint.ZERO)) {
      throw new Error("derived point at infinity (retry next index)");
    }
    zeroize(I, IL);
    return new HDPublicKey(child.toRawBytes(true), IR, {
      depth: this.meta.depth + 1,
      parentFingerprint: this.fingerprint,
      childIndex: index,
    });
  }

  derivePath(path: string): HDPublicKey {
    // eslint-disable-next-line @typescript-eslint/no-this-alias
    let node: HDPublicKey = this;
    for (const index of parseRelativePath(path)) {
      node = node.deriveChild(index);
    }
    return node;
  }

  toExtended(version: number = VERSIONS.xprv.public): string {
    return serializeExtended(version, this.meta, this.chainCode, this.publicKey);
  }
}

export class HDPrivateKey {
  constructor(
    /** 32-byte private key. Owned by this object; wipe() zeroizes it. */
    public readonly privateKey: Uint8Array,
    public readonly chainCode: Uint8Array,
    public readonly meta: HDNodeMeta,
  ) {
    if (privateKey.length !== 32) throw new Error("private key must be 32 bytes");
    if (chainCode.length !== 32) throw new Error("chain code must be 32 bytes");
    assertValidPrivateKey(bytesToBigInt(privateKey));
  }

  /** HMAC-SHA512(key="Bitcoin seed") over the BIP39 seed. */
  static fromSeed(seed: Uint8Array): HDPrivateKey {
    if (seed.length < 16 || seed.length > 64) throw new Error("seed must be 16..64 bytes");
    const I = hmac(sha512, new TextEncoder().encode("Bitcoin seed"), seed);
    const key = I.slice(0, 32);
    const chainCode = I.slice(32);
    zeroize(I);
    return new HDPrivateKey(key, chainCode, { depth: 0, parentFingerprint: 0, childIndex: 0 });
  }

  get publicKey(): Uint8Array {
    return secp256k1.getPublicKey(this.privateKey, true);
  }

  get fingerprint(): number {
    const h = hash160(this.publicKey);
    return new DataView(h.buffer, h.byteOffset, 4).getUint32(0, false);
  }

  neutered(): HDPublicKey {
    return new HDPublicKey(this.publicKey, this.chainCode, { ...this.meta });
  }

  deriveChild(index: number): HDPrivateKey {
    if (!Number.isInteger(index) || index < 0 || index > 0xffffffff) {
      throw new Error("invalid child index");
    }
    const hardened = index >= HARDENED_OFFSET;
    const data = hardened
      ? concatBytes(new Uint8Array([0]), this.privateKey, u32be(index))
      : concatBytes(this.publicKey, u32be(index));
    const I = hmac(sha512, this.chainCode, data);
    const IL = I.slice(0, 32);
    const IR = I.slice(32);
    const ilScalar = bytesToBigInt(IL);
    if (ilScalar >= CURVE_N) throw new Error("derived key outside curve order (retry next index)");
    const childScalar = (ilScalar + bytesToBigInt(this.privateKey)) % CURVE_N;
    assertValidPrivateKey(childScalar);
    const childKey = bigIntTo32(childScalar);
    zeroize(I, IL, data);
    return new HDPrivateKey(childKey, IR, {
      depth: this.meta.depth + 1,
      parentFingerprint: this.fingerprint,
      childIndex: index,
    });
  }

  derivePath(path: string): HDPrivateKey {
    // eslint-disable-next-line @typescript-eslint/no-this-alias
    let node: HDPrivateKey = this;
    for (const index of parseRelativePath(path)) {
      const next = node.deriveChild(index);
      if (node !== this) node.wipe();
      node = next;
    }
    return node;
  }

  toExtended(version: number = VERSIONS.xprv.private): string {
    return serializeExtended(
      version,
      this.meta,
      this.chainCode,
      concatBytes(new Uint8Array([0]), this.privateKey),
    );
  }

  /** Zeroize private material. The object must not be used afterwards. */
  wipe(): void {
    zeroize(this.privateKey, this.chainCode);
  }
}

function serializeExtended(
  version: number,
  meta: HDNodeMeta,
  chainCode: Uint8Array,
  keyData: Uint8Array,
): string {
  if (meta.depth < 0 || meta.depth > 255) throw new Error("invalid depth");
  const payload = concatBytes(
    u32be(version),
    new Uint8Array([meta.depth]),
    u32be(meta.parentFingerprint),
    u32be(meta.childIndex),
    chainCode,
    keyData,
  );
  return base58check.encode(payload);
}

export interface ParsedExtendedKey {
  version: number;
  key: HDPrivateKey | HDPublicKey;
  isPrivate: boolean;
}

/** Parse any xprv/xpub/yprv/ypub/zprv/zpub/tprv/... string with full validation. */
export function parseExtendedKey(encoded: string): ParsedExtendedKey {
  const payload = base58check.decode(encoded);
  if (payload.length !== 78) throw new Error("extended key must decode to 78 bytes");
  const view = new DataView(payload.buffer, payload.byteOffset);
  const version = view.getUint32(0, false);
  const depth = payload[4]!;
  const parentFingerprint = view.getUint32(5, false);
  const childIndex = view.getUint32(9, false);
  const chainCode = payload.slice(13, 45);
  const keyData = payload.slice(45, 78);
  const meta: HDNodeMeta = { depth, parentFingerprint, childIndex };

  if (depth === 0 && (parentFingerprint !== 0 || childIndex !== 0)) {
    throw new Error("master key must have zero parent fingerprint and index");
  }

  const known = Object.values(VERSIONS);
  const isPrivate = known.some((v) => v.private === version);
  const isPublic = known.some((v) => v.public === version);
  if (!isPrivate && !isPublic) throw new Error("unknown extended key version");

  if (isPrivate) {
    if (keyData[0] !== 0) throw new Error("invalid private key prefix");
    return { version, key: new HDPrivateKey(keyData.slice(1), chainCode, meta), isPrivate: true };
  }
  return { version, key: new HDPublicKey(keyData, chainCode, meta), isPrivate: false };
}

/** Parse "m/84'/0'/0'" or relative "0/12" into child indices. Accepts ' and h. */
export function parsePath(path: string): number[] {
  const trimmed = path.trim();
  if (trimmed === "m" || trimmed === "") return [];
  const withoutMaster = trimmed.startsWith("m/") ? trimmed.slice(2) : trimmed;
  return parseRelativePath(withoutMaster);
}

function parseRelativePath(path: string): number[] {
  if (path === "") return [];
  return path.split("/").map((part) => {
    const hardened = part.endsWith("'") || part.endsWith("h") || part.endsWith("H");
    const numStr = hardened ? part.slice(0, -1) : part;
    if (!/^\d+$/.test(numStr)) throw new Error(`invalid path segment: ${part}`);
    const num = parseInt(numStr, 10);
    if (num >= HARDENED_OFFSET) throw new Error(`index too large: ${part}`);
    return hardened ? num + HARDENED_OFFSET : num;
  });
}
