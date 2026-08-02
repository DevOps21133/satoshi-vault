import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  HDPrivateKey,
  parseExtendedKey,
  parsePath,
  HARDENED_OFFSET,
} from "../src/bip32/hdkey.js";
import { hexToBytes } from "../src/util/bytes.js";

const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(readFileSync(join(here, "vectors/bip32.json"), "utf8")) as {
  vectors: { seed: string; chains: { path: string; xpub: string; xprv: string }[] }[];
  invalid: string[];
};

describe("BIP32 official vectors", () => {
  vectors.vectors.forEach((vector, vi) => {
    for (const chain of vector.chains) {
      it(`vector ${vi + 1} ${chain.path}`, () => {
        const master = HDPrivateKey.fromSeed(hexToBytes(vector.seed));
        const node = chain.path === "m" ? master : master.derivePath(chain.path.slice(2));
        expect(node.toExtended()).toBe(chain.xprv);
        expect(node.neutered().toExtended()).toBe(chain.xpub);
      });
    }
  });

  it("public derivation (CKDpub) matches private derivation for non-hardened chains", () => {
    const master = HDPrivateKey.fromSeed(hexToBytes(vectors.vectors[1]!.seed));
    const accountPriv = master.deriveChild(0);
    const accountPub = master.neutered().deriveChild(0);
    expect(accountPub.toExtended()).toBe(accountPriv.neutered().toExtended());
    const childPub = accountPub.deriveChild(5).deriveChild(9);
    const childPriv = accountPriv.deriveChild(5).deriveChild(9);
    expect(childPub.toExtended()).toBe(childPriv.neutered().toExtended());
  });

  it("round-trips through parseExtendedKey", () => {
    const master = HDPrivateKey.fromSeed(hexToBytes(vectors.vectors[0]!.seed));
    const xprv = master.toExtended();
    const parsed = parseExtendedKey(xprv);
    expect(parsed.isPrivate).toBe(true);
    expect((parsed.key as HDPrivateKey).toExtended()).toBe(xprv);
    const xpub = master.neutered().toExtended();
    const parsedPub = parseExtendedKey(xpub);
    expect(parsedPub.isPrivate).toBe(false);
  });
});

describe("BIP32 invalid keys (vector 5)", () => {
  const vecs = JSON.parse(readFileSync(join(here, "vectors/bip32.json"), "utf8")) as { invalid: string[] };
  vecs.invalid.forEach((encoded) => {
    it(`rejects ${encoded.slice(0, 20)}…`, () => {
      expect(() => parseExtendedKey(encoded)).toThrow();
    });
  });
});

describe("path parsing", () => {
  it("parses BIP84 account path", () => {
    expect(parsePath("m/84'/0'/0'")).toEqual([
      84 + HARDENED_OFFSET,
      0 + HARDENED_OFFSET,
      0 + HARDENED_OFFSET,
    ]);
  });
  it("accepts h suffix and rejects garbage", () => {
    expect(parsePath("m/86h/0h/0h")).toEqual(parsePath("m/86'/0'/0'"));
    expect(() => parsePath("m/84'/x")).toThrow();
    expect(() => parsePath("m/-1")).toThrow();
    expect(() => parsePath("m/2147483648")).toThrow();
  });
  it("hardened derivation from public key throws", () => {
    const master = HDPrivateKey.fromSeed(new Uint8Array(32).fill(7));
    expect(() => master.neutered().deriveChild(HARDENED_OFFSET)).toThrow();
  });
});
