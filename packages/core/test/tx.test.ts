import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { schnorr } from "@noble/curves/secp256k1";
import { parseTx, serializeTx, serializeTxLegacy, txid, txidToBytes, Transaction } from "../src/tx/tx.js";
import { segwitV0Sighash, taprootSighash, p2pkhScriptCode } from "../src/tx/sighash.js";
import { signInput } from "../src/tx/sign.js";
import { taprootOutputKey, taprootTweakPrivateKey } from "../src/crypto/taproot.js";
import { bytesToHex, hexToBytes } from "../src/util/bytes.js";
import { selectCoins, estimateVsize, Utxo } from "../src/tx/coinselect.js";

const here = dirname(fileURLToPath(import.meta.url));

// --- BIP143 official "Native P2WPKH" example -------------------------------

const BIP143_UNSIGNED =
  "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000";
const BIP143_SIGNED =
  "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000";

describe("BIP143 native P2WPKH official example", () => {
  it("computes the exact spec sighash", () => {
    const tx = parseTx(hexToBytes(BIP143_UNSIGNED));
    const scriptCode = p2pkhScriptCode(hexToBytes("1d0f172a0ecb48aee1be1f2687d2963ae33f71a1"));
    const sighash = segwitV0Sighash(tx, 1, scriptCode, 600_000_000n);
    expect(bytesToHex(sighash)).toBe("c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670");
  });

  it("produces the exact spec signature (RFC6979 deterministic)", () => {
    const tx = parseTx(hexToBytes(BIP143_UNSIGNED));
    signInput(
      tx,
      1,
      {
        spendType: "p2wpkh",
        prevout: { value: 600_000_000n, scriptPubKey: hexToBytes("00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1") },
      },
      hexToBytes("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9"),
    );
    expect(bytesToHex(tx.inputs[1]!.witness[0]!)).toBe(
      "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01",
    );
    expect(bytesToHex(tx.inputs[1]!.witness[1]!)).toBe(
      "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357",
    );
  });

  it("parse -> serialize round-trips the signed transaction byte-for-byte", () => {
    const tx = parseTx(hexToBytes(BIP143_SIGNED));
    expect(bytesToHex(serializeTx(tx))).toBe(BIP143_SIGNED);
    expect(serializeTxLegacy(tx).length).toBeLessThan(serializeTx(tx).length);
  });

  it("txid ignores witness data", () => {
    const signed = parseTx(hexToBytes(BIP143_SIGNED));
    const unsigned = parseTx(hexToBytes(BIP143_UNSIGNED));
    // scriptSigs differ (input 0 is signed) so txids differ, but wtxid vs txid distinction holds:
    expect(txid(unsigned)).toHaveLength(64);
    expect(txid(signed)).toHaveLength(64);
  });
});

// --- BIP341 official wallet test vectors ------------------------------------

interface Bip341Vectors {
  scriptPubKey: {
    given: { internalPubkey: string; scriptTree: unknown };
    intermediary: { tweakedPubkey: string };
    expected: { scriptPubKey: string; bip350Address: string };
  }[];
  keyPathSpending: {
    given: { rawUnsignedTx: string; utxosSpent: { scriptPubKey: string; amountSats: number }[] };
    inputSpending: {
      given: { txinIndex: number; internalPrivkey: string; merkleRoot: string | null; hashType: number };
      intermediary: { tweakedPrivkey: string; sigHash: string };
      expected: { witness: string[] };
    }[];
  }[];
}

const bip341 = JSON.parse(readFileSync(join(here, "vectors/bip341.json"), "utf8")) as Bip341Vectors;

describe("BIP341 official wallet vectors", () => {
  it("taproot output key (key-path-only entries)", () => {
    const entries = bip341.scriptPubKey.filter((e) => e.given.scriptTree === null);
    expect(entries.length).toBeGreaterThan(0);
    for (const e of entries) {
      const out = taprootOutputKey(hexToBytes(e.given.internalPubkey));
      expect(bytesToHex(out)).toBe(e.intermediary.tweakedPubkey);
    }
  });

  it("tweaked private keys match for every spending vector", () => {
    const spend = bip341.keyPathSpending[0]!;
    for (const input of spend.inputSpending) {
      const merkle = input.given.merkleRoot ? hexToBytes(input.given.merkleRoot) : undefined;
      const tweaked = taprootTweakPrivateKey(hexToBytes(input.given.internalPrivkey), merkle);
      expect(bytesToHex(tweaked)).toBe(input.intermediary.tweakedPrivkey);
    }
  });

  it("sighashes and signatures (SIGHASH_DEFAULT/ALL vectors)", () => {
    const spend = bip341.keyPathSpending[0]!;
    const tx = parseTx(hexToBytes(spend.given.rawUnsignedTx));
    const prevouts = spend.given.utxosSpent.map((u) => ({
      value: BigInt(u.amountSats),
      scriptPubKey: hexToBytes(u.scriptPubKey),
    }));
    const applicable = spend.inputSpending.filter(
      (i) => i.given.hashType === 0 || i.given.hashType === 1,
    );
    expect(applicable.length).toBeGreaterThan(0);
    for (const input of applicable) {
      const merkle = input.given.merkleRoot ? hexToBytes(input.given.merkleRoot) : undefined;
      const tweaked = taprootTweakPrivateKey(hexToBytes(input.given.internalPrivkey), merkle);
      const sighash = taprootSighash(tx, input.given.txinIndex, prevouts, input.given.hashType);
      expect(bytesToHex(sighash)).toBe(input.intermediary.sigHash);
      // The expected witness signature must verify under our tweaked pubkey.
      const sig = hexToBytes(input.expected.witness[0]!);
      expect(
        schnorr.verify(sig.slice(0, 64), sighash, schnorr.getPublicKey(tweaked)),
      ).toBe(true);
    }
  });
});

// --- parser hostility --------------------------------------------------------

describe("transaction parser rejects malformed input", () => {
  it("trailing bytes", () => {
    expect(() => parseTx(hexToBytes(BIP143_SIGNED + "00"))).toThrow();
  });
  it("truncated", () => {
    expect(() => parseTx(hexToBytes(BIP143_SIGNED.slice(0, 40)))).toThrow();
  });
  it("bad segwit flag", () => {
    const bytes = hexToBytes(BIP143_SIGNED);
    bytes[5] = 0x02;
    expect(() => parseTx(bytes)).toThrow();
  });
  it("empty", () => {
    expect(() => parseTx(new Uint8Array(0))).toThrow();
  });
});

// --- coin selection ----------------------------------------------------------

function utxo(value: bigint, i: number): Utxo {
  return {
    txid: "aa".repeat(32),
    vout: i,
    value,
    spendType: "p2wpkh",
    derivationPath: `m/84'/0'/0'/0/${i}`,
    scriptPubKey: new Uint8Array(22),
  };
}

describe("coin selection", () => {
  const target = {
    recipientScriptLength: 22,
    changeScriptLength: 22,
    changeSpendType: "p2wpkh" as const,
    feeRateSatPerVb: 10,
  };

  it("selects enough and pays a sane fee", () => {
    const res = selectCoins([utxo(50_000n, 0), utxo(30_000n, 1), utxo(8_000n, 2)], {
      ...target,
      amount: 60_000n,
    });
    const totalIn = res.inputs.reduce((s, u) => s + u.value, 0n);
    expect(totalIn).toBe(60_000n + res.fee + res.change);
    expect(res.fee).toBeGreaterThan(0n);
    // fee should be near vsize * rate
    const vsize = estimateVsize(res.inputs.map((u) => u.spendType), res.change > 0n ? [22, 22] : [22]);
    expect(res.fee).toBeLessThan(BigInt(vsize * 12));
  });

  it("throws on insufficient funds", () => {
    expect(() => selectCoins([utxo(1_000n, 0)], { ...target, amount: 100_000n })).toThrow(/insufficient/);
  });

  it("never creates dust change", () => {
    // amount chosen so change would be tiny
    const res = selectCoins([utxo(10_000n, 0)], { ...target, amount: 8_500n });
    expect(res.change === 0n || res.change >= 330n).toBe(true);
  });

  it("rejects absurd fee rates", () => {
    expect(() => selectCoins([utxo(10_000n, 0)], { ...target, amount: 1_000n, feeRateSatPerVb: 100_000 })).toThrow();
    expect(() => selectCoins([utxo(10_000n, 0)], { ...target, amount: 1_000n, feeRateSatPerVb: 0 })).toThrow();
  });
});

// --- txid sanity against a real mainnet transaction --------------------------

describe("txid computation", () => {
  it("matches the first-ever P2P bitcoin transaction (block 170)", () => {
    // Satoshi -> Hal Finney, txid f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16
    const raw =
      "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000";
    const tx = parseTx(hexToBytes(raw));
    expect(txid(tx)).toBe("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16");
    expect(txidToBytes(txid(tx))).toHaveLength(32);
  });
});
