import { describe, it, expect } from "vitest";
import { mnemonicToSeed } from "../src/bip39/mnemonic.js";
import { HDPrivateKey } from "../src/bip32/hdkey.js";
import {
  p2pkhAddress,
  p2shP2wpkhAddress,
  p2wpkhAddress,
  p2trAddress,
  decodeAddress,
  scriptToAddress,
} from "../src/address/address.js";
import { MAINNET, TESTNET } from "../src/address/network.js";
import { bytesToHex } from "../src/util/bytes.js";

// The standard test mnemonic used by BIP49/84/86 official vectors.
const MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".split(" ");

function derive(path: string) {
  const seed = mnemonicToSeed(MNEMONIC);
  const master = HDPrivateKey.fromSeed(seed);
  return master.derivePath(path.slice(2));
}

describe("address derivation against official BIP vectors", () => {
  it("BIP84 P2WPKH mainnet (spec vectors)", () => {
    expect(bytesToHex(derive("m/84'/0'/0'/0/0").publicKey)).toBe(
      "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c",
    );
    expect(p2wpkhAddress(derive("m/84'/0'/0'/0/0").publicKey, MAINNET)).toBe(
      "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
    );
    expect(p2wpkhAddress(derive("m/84'/0'/0'/0/1").publicKey, MAINNET)).toBe(
      "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g",
    );
    expect(p2wpkhAddress(derive("m/84'/0'/0'/1/0").publicKey, MAINNET)).toBe(
      "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el",
    );
  });

  it("BIP86 P2TR mainnet (spec vectors)", () => {
    expect(p2trAddress(derive("m/86'/0'/0'/0/0").publicKey, MAINNET)).toBe(
      "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
    );
    expect(p2trAddress(derive("m/86'/0'/0'/0/1").publicKey, MAINNET)).toBe(
      "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh",
    );
    expect(p2trAddress(derive("m/86'/0'/0'/1/0").publicKey, MAINNET)).toBe(
      "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7",
    );
  });

  it("BIP49 P2SH-P2WPKH testnet (spec vector)", () => {
    expect(p2shP2wpkhAddress(derive("m/49'/1'/0'/0/0").publicKey, TESTNET)).toBe(
      "2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2",
    );
  });

  it("BIP44 P2PKH mainnet (widely published vector)", () => {
    expect(p2pkhAddress(derive("m/44'/0'/0'/0/0").publicKey, MAINNET)).toBe(
      "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
    );
  });
});

describe("address decoding (hostile input)", () => {
  const valid = [
    "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
    "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
    "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
    "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
  ];
  for (const addr of valid) {
    it(`round-trips ${addr.slice(0, 12)}…`, () => {
      const decoded = decodeAddress(addr, MAINNET);
      expect(scriptToAddress(decoded.scriptPubKey, MAINNET)).toBe(addr);
    });
  }

  it("rejects checksum tampering (address poisoning)", () => {
    expect(() => decodeAddress("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyv", MAINNET)).toThrow();
    expect(() => decodeAddress("1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabB", MAINNET)).toThrow();
  });

  it("rejects wrong-network addresses", () => {
    expect(() => decodeAddress("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", MAINNET)).toThrow();
    expect(() => decodeAddress("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", TESTNET)).toThrow();
    expect(() => decodeAddress("2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2", MAINNET)).toThrow();
  });

  it("rejects garbage, empty, oversized", () => {
    expect(() => decodeAddress("", MAINNET)).toThrow();
    expect(() => decodeAddress("not-an-address", MAINNET)).toThrow();
    expect(() => decodeAddress("bc1" + "q".repeat(200), MAINNET)).toThrow();
  });

  it("rejects future witness versions (no blind sends to unknown scripts)", () => {
    // witness v2 program — validly encoded bech32m but unsupported.
    expect(() => decodeAddress("bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs", MAINNET)).toThrow();
  });
});
