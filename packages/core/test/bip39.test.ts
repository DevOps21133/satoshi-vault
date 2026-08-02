import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  entropyToMnemonic,
  mnemonicToEntropy,
  mnemonicToSeed,
  validateMnemonic,
} from "../src/bip39/mnemonic.js";
import { HDPrivateKey } from "../src/bip32/hdkey.js";
import { bytesToHex, hexToBytes } from "../src/util/bytes.js";

const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(readFileSync(join(here, "vectors/bip39.json"), "utf8")) as {
  english: [string, string, string, string][];
};

// Official Trezor vectors use passphrase "TREZOR".
describe("BIP39 official vectors", () => {
  for (const [entropyHex, mnemonic, seedHex, xprv] of vectors.english) {
    it(`entropy ${entropyHex.slice(0, 16)}…`, () => {
      const words = mnemonic.split(" ");
      expect(entropyToMnemonic(hexToBytes(entropyHex)).join(" ")).toBe(mnemonic);
      expect(bytesToHex(mnemonicToEntropy(words))).toBe(entropyHex);
      const seed = mnemonicToSeed(words, "TREZOR");
      expect(bytesToHex(seed)).toBe(seedHex);
      expect(HDPrivateKey.fromSeed(seed).toExtended()).toBe(xprv);
      expect(validateMnemonic(words).ok).toBe(true);
    });
  }
});

describe("BIP39 validation", () => {
  it("rejects bad checksum", () => {
    const words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon".split(" ");
    expect(validateMnemonic(words)).toEqual({ ok: false, error: "checksum" });
  });
  it("rejects unknown words", () => {
    const words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon nakamoto".split(" ");
    const res = validateMnemonic(words);
    expect(res.ok).toBe(false);
    expect(res.error).toBe("unknown-word");
  });
  it("rejects wrong word counts", () => {
    expect(validateMnemonic(["abandon"]).error).toBe("word-count");
  });
  it("rejects non-standard entropy sizes", () => {
    expect(() => entropyToMnemonic(new Uint8Array(17))).toThrow();
    expect(() => entropyToMnemonic(new Uint8Array(0))).toThrow();
  });
  it("normalizes case and whitespace", () => {
    const words = "Abandon ABANDON abandon abandon abandon abandon abandon abandon abandon abandon abandon About ".split(" ").map((w) => w);
    expect(validateMnemonic(words.filter((w) => w !== "")).ok).toBe(true);
  });
});
