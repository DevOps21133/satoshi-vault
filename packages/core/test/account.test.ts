import { describe, it, expect } from "vitest";
import { mnemonicToSeed } from "../src/bip39/mnemonic.js";
import { HDPrivateKey } from "../src/bip32/hdkey.js";
import { MAINNET } from "../src/address/network.js";
import {
  exportAccount,
  WatchAccount,
  accountExportToJson,
  accountExportFromJson,
} from "../src/wallet/account.js";
import { EsploraClient } from "../src/net/esplora.js";

const MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".split(" ");

function master(): HDPrivateKey {
  return HDPrivateKey.fromSeed(mnemonicToSeed(MNEMONIC));
}

describe("account export/import (Signer -> Wallet handoff)", () => {
  it("BIP84 export matches the official spec zpub", () => {
    const m = master();
    const exported = exportAccount(m, "p2wpkh", MAINNET);
    // Account-level zpub from the BIP84 test vectors.
    expect(exported.xpub).toBe(
      "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs",
    );
    expect(exported.path).toBe("m/84'/0'/0'");
    expect(exported.masterFingerprint).toBe("73c5da0a"); // BIP84 vector fingerprint
    m.wipe();
  });

  it("watch account derives the same addresses as the private side", () => {
    const m = master();
    const exported = exportAccount(m, "p2wpkh", MAINNET);
    const watch = new WatchAccount(exported);
    expect(watch.addressAt(0, 0)).toBe("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    expect(watch.addressAt(0, 1)).toBe("bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g");
    expect(watch.addressAt(1, 0)).toBe("bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el");
    expect(watch.fullPath(0, 7)).toEqual([84 + 0x80000000, 0x80000000, 0x80000000, 0, 7]);
    m.wipe();
  });

  it("taproot watch account matches BIP86 vectors", () => {
    const m = master();
    const watch = new WatchAccount(exportAccount(m, "p2tr", MAINNET));
    expect(watch.addressAt(0, 0)).toBe("bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr");
    m.wipe();
  });

  it("JSON round trip", () => {
    const m = master();
    const exported = exportAccount(m, "p2wpkh", MAINNET);
    const back = accountExportFromJson(accountExportToJson(exported));
    expect(back).toEqual(exported);
    expect(() => new WatchAccount(back)).not.toThrow();
    m.wipe();
  });

  it("refuses private key material", () => {
    const m = master();
    const exported = exportAccount(m, "p2wpkh", MAINNET);
    const account = m.derivePath("84'/0'/0'");
    const hostile = { ...exported, xpub: account.toExtended() };
    expect(() => new WatchAccount(hostile)).toThrow(/private key/);
    account.wipe();
    m.wipe();
  });

  it("refuses mismatched script type / version / path", () => {
    const m = master();
    const good = exportAccount(m, "p2wpkh", MAINNET);
    expect(() => new WatchAccount({ ...good, scriptType: "p2pkh" })).toThrow();
    expect(() => new WatchAccount({ ...good, path: "m/44'/0'/0'" })).toThrow();
    expect(() => new WatchAccount({ ...good, network: "testnet" })).toThrow();
    expect(() => new WatchAccount({ ...good, network: "dogecoin" })).toThrow(/unknown network/);
    m.wipe();
  });

  it("rejects malformed JSON payloads", () => {
    const enc = (s: string) => new TextEncoder().encode(s);
    expect(() => accountExportFromJson(enc("not json"))).toThrow();
    expect(() => accountExportFromJson(enc("{}"))).toThrow(/malformed/);
    expect(() => accountExportFromJson(enc('{"version":2}'))).toThrow(/malformed/);
    expect(() => accountExportFromJson(new Uint8Array(10_000))).toThrow(/too large/);
  });
});

describe("esplora client (stubbed transport)", () => {
  function stub(handler: (url: string, init?: RequestInit) => { status?: number; body: string }) {
    const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const { status = 200, body } = handler(String(input), init);
      return new Response(body, { status });
    }) as typeof fetch;
    return new EsploraClient("https://esplora.example", fetchImpl);
  }

  it("parses UTXOs and converts values to bigint", async () => {
    const client = stub(() => ({
      body: JSON.stringify([
        {
          txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
          vout: 0,
          value: 5_000_000_000,
          status: { confirmed: true, block_height: 170 },
        },
      ]),
    }));
    const utxos = await client.getAddressUtxos("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    expect(utxos).toHaveLength(1);
    expect(utxos[0]!.value).toBe(5_000_000_000n);
    expect(utxos[0]!.confirmed).toBe(true);
    expect(utxos[0]!.blockHeight).toBe(170);
  });

  it("rejects malformed UTXO entries", async () => {
    const client = stub(() => ({ body: JSON.stringify([{ txid: "xx", vout: 0, value: 1 }]) }));
    await expect(client.getAddressUtxos("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")).rejects.toThrow();
  });

  it("rejects negative and unsafe values", async () => {
    const client = stub(() => ({
      body: JSON.stringify([
        {
          txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
          vout: 0,
          value: -5,
        },
      ]),
    }));
    await expect(client.getAddressUtxos("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")).rejects.toThrow();
  });

  it("validates txids before requesting and after broadcasting", async () => {
    const client = stub(() => ({ body: "deadbeef" }));
    await expect(client.getTxHex("nothex")).rejects.toThrow();
    await expect(client.broadcastTx("zzzz")).rejects.toThrow(/malformed/);
  });

  it("propagates HTTP errors with context", async () => {
    const client = stub(() => ({ status: 400, body: "sendrawtransaction RPC error" }));
    await expect(client.broadcastTx("0200")).rejects.toThrow(/esplora 400/);
  });

  it("filters implausible fee estimates", async () => {
    const client = stub(() => ({
      body: JSON.stringify({ "1": 25.5, "6": 12.1, "144": 1.5, evil: 5, "3": -2 }),
    }));
    const fees = await client.getFeeEstimates();
    expect(fees["1"]).toBe(25.5);
    expect(fees["evil"]).toBeUndefined();
    expect(fees["3"]).toBeUndefined();
  });

  it("refuses non-http(s) endpoints", () => {
    expect(() => new EsploraClient("file:///etc/passwd")).toThrow();
  });
});
