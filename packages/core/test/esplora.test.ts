import { describe, it, expect } from "vitest";
import { EsploraClient } from "../src/net/esplora.js";

/** A fetch stand-in that returns one canned JSON body for every request. */
function fetchReturning(body: unknown): typeof fetch {
  return (async () =>
    new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } })) as typeof fetch;
}

const ADDRESS = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
const TXID = "aa".repeat(32);

describe("esplora client treats the server as hostile", () => {
  it("rejects a UTXO worth more than all the bitcoin that will ever exist", async () => {
    const client = new EsploraClient(
      "https://example.invalid",
      fetchReturning([{ txid: TXID, vout: 0, value: Number.MAX_SAFE_INTEGER, status: { confirmed: true } }]),
    );
    await expect(client.getAddressUtxos(ADDRESS)).rejects.toThrow(/malformed UTXO value/);
  });

  it("accepts a UTXO exactly at MAX_MONEY", async () => {
    const client = new EsploraClient(
      "https://example.invalid",
      fetchReturning([{ txid: TXID, vout: 0, value: 2_100_000_000_000_000, status: { confirmed: true } }]),
    );
    const utxos = await client.getAddressUtxos(ADDRESS);
    expect(utxos[0]!.value).toBe(2_100_000_000_000_000n);
  });

  it("a negative block height is reported as no height, not as a height", async () => {
    const client = new EsploraClient(
      "https://example.invalid",
      fetchReturning({ confirmed: true, block_height: -5 }),
    );
    expect((await client.getTxStatus(TXID)).blockHeight).toBe(null);
  });

  it("refuses an endpoint carrying a query or fragment", () => {
    // Request paths are appended by concatenation, so these would corrupt
    // every single request.
    expect(() => new EsploraClient("https://example.invalid/api?token=x")).toThrow(/query or fragment/);
    expect(() => new EsploraClient("https://example.invalid/api#frag")).toThrow(/query or fragment/);
    expect(() => new EsploraClient("https://example.invalid/api")).not.toThrow();
  });
});
