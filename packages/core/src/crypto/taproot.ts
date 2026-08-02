/**
 * BIP340/341 taproot key tweaking, using only audited @noble/curves operations.
 * We support key-path-only outputs (no script tree), the BIP86 standard for
 * single-sig taproot wallets: merkle root is absent, so
 *   tweak t = taggedHash("TapTweak", xonly(P))
 *   output key Q = P + t*G
 * Verified against the official BIP341 wallet test vectors and BIP86 vectors.
 */

import { secp256k1, schnorr } from "@noble/curves/secp256k1";
import { taggedHash } from "./hash.js";
import { zeroize } from "../util/bytes.js";

const Point = secp256k1.ProjectivePoint;
const CURVE_N = secp256k1.CURVE.n;

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

/** 32-byte x-only public key from a 33-byte compressed key. */
export function xOnly(pubkey33: Uint8Array): Uint8Array {
  if (pubkey33.length === 32) return pubkey33;
  if (pubkey33.length !== 33) throw new Error("expected 32/33-byte public key");
  return pubkey33.slice(1);
}

/**
 * BIP341 output key. Wallet code always calls this without merkleRoot
 * (key-path-only, BIP86); the parameter exists so the official test vectors
 * can exercise the script-tree tweak too.
 */
export function taprootOutputKey(internalXOnly: Uint8Array, merkleRoot?: Uint8Array): Uint8Array {
  if (internalXOnly.length !== 32) throw new Error("internal key must be 32 bytes (x-only)");
  const t = bytesToBigInt(
    merkleRoot ? taggedHash("TapTweak", internalXOnly, merkleRoot) : taggedHash("TapTweak", internalXOnly),
  );
  if (t >= CURVE_N) throw new Error("tap tweak out of range");
  const P = schnorr.utils.lift_x(bytesToBigInt(internalXOnly));
  const Q = P.add(Point.BASE.multiply(t));
  return schnorr.utils.pointToBytes(Q);
}

/**
 * Tweak a private key for a taproot key-path spend.
 * Per BIP341: if the internal point has odd Y, negate the private key first.
 * Caller must zeroize the returned key after signing.
 */
export function taprootTweakPrivateKey(privateKey: Uint8Array, merkleRoot?: Uint8Array): Uint8Array {
  if (privateKey.length !== 32) throw new Error("private key must be 32 bytes");
  let d = bytesToBigInt(privateKey) % CURVE_N;
  if (d === 0n) throw new Error("invalid private key");
  const P = Point.BASE.multiply(d);
  // schnorr/x-only convention: use the key whose point has even Y.
  const affine = P.toAffine();
  if ((affine.y & 1n) === 1n) d = CURVE_N - d;
  const xonly = bigIntTo32(affine.x);
  const t = bytesToBigInt(
    merkleRoot ? taggedHash("TapTweak", xonly, merkleRoot) : taggedHash("TapTweak", xonly),
  );
  if (t >= CURVE_N) throw new Error("tap tweak out of range");
  const tweaked = (d + t) % CURVE_N;
  if (tweaked === 0n) throw new Error("tweaked key is zero");
  const out = bigIntTo32(tweaked);
  zeroize(xonly);
  return out;
}
