/**
 * Esplora HTTP client (Blockstream-style API) for the watch-only wallet.
 *
 * Security posture:
 * - The server is UNTRUSTED for integrity of anything we can verify locally:
 *   scripts/addresses are re-derived from the xpub, previous transactions are
 *   re-hashed and their txids checked. The server can lie about confirmations
 *   or hide UTXOs (liveness), but cannot make the wallet sign for the wrong
 *   script or amount — those are re-verified by the Signer from PSBT data.
 * - The endpoint is user-configurable (own node strongly recommended; a
 *   .onion endpoint used through a Tor-proxied fetch keeps xpub privacy).
 * - Every response is size-capped, schema-validated, and parsed as hostile.
 * - No cookies, no credentials, no redirects.
 */

import { MAX_MONEY, txidToBytes } from "../tx/tx.js";

const MAX_RESPONSE_BYTES = 5_000_000;
const REQUEST_TIMEOUT_MS = 30_000;

export interface EsploraUtxo {
  txid: string;
  vout: number;
  value: bigint;
  confirmed: boolean;
  blockHeight: number | null;
}

export interface EsploraTxStatus {
  confirmed: boolean;
  blockHeight: number | null;
}

export interface FeeEstimates {
  /** sat/vB by confirmation target (e.g. 1, 3, 6, 144). */
  [target: string]: number;
}

export class EsploraClient {
  private readonly baseUrl: string;

  // The default must stay an arrow wrapper: a bare `fetch` reference is
  // unbound, and calling it as `this.fetchImpl(...)` makes Chromium throw
  // "Illegal invocation" (fetch invoked with `this` !== window).
  constructor(baseUrl: string, private readonly fetchImpl: typeof fetch = (input, init) => fetch(input, init)) {
    const url = new URL(baseUrl);
    if (url.protocol !== "https:" && url.protocol !== "http:") {
      throw new Error("esplora URL must be http(s)");
    }
    // Paths are appended by string concatenation, so a query or fragment in the
    // configured endpoint would silently corrupt every request path.
    if (url.search || url.hash) throw new Error("esplora URL must not contain a query or fragment");
    this.baseUrl = baseUrl.replace(/\/+$/, "");
  }

  private async request(path: string, init?: RequestInit): Promise<string> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
      const res = await this.fetchImpl(`${this.baseUrl}${path}`, {
        ...init,
        signal: controller.signal,
        redirect: "error",
        credentials: "omit",
        referrerPolicy: "no-referrer",
      });
      const body = await readBodyCapped(res, MAX_RESPONSE_BYTES);
      if (!res.ok) throw new Error(`esplora ${res.status}: ${body.slice(0, 200)}`);
      return body;
    } finally {
      clearTimeout(timer);
    }
  }

  private async requestJson(path: string): Promise<unknown> {
    const body = await this.request(path);
    try {
      return JSON.parse(body);
    } catch {
      throw new Error("esplora returned invalid JSON");
    }
  }

  async getTipHeight(): Promise<number> {
    const body = await this.request("/blocks/tip/height");
    const height = Number(body.trim());
    if (!Number.isSafeInteger(height) || height < 0 || height > 10_000_000) {
      throw new Error("implausible tip height");
    }
    return height;
  }

  async getAddressUtxos(address: string): Promise<EsploraUtxo[]> {
    assertSaneAddressString(address);
    const data = await this.requestJson(`/address/${encodeURIComponent(address)}/utxo`);
    if (!Array.isArray(data)) throw new Error("expected UTXO array");
    if (data.length > 10_000) throw new Error("implausible UTXO count");
    return data.map((entry) => parseUtxo(entry));
  }

  /** True if the address has any transaction history (for gap-limit scanning). */
  async addressHasHistory(address: string): Promise<boolean> {
    assertSaneAddressString(address);
    const data = await this.requestJson(`/address/${encodeURIComponent(address)}`);
    if (typeof data !== "object" || data === null) throw new Error("malformed address info");
    const stats = (data as Record<string, unknown>)["chain_stats"];
    const mempool = (data as Record<string, unknown>)["mempool_stats"];
    const txCount = (s: unknown): number => {
      if (typeof s !== "object" || s === null) return 0;
      const n = (s as Record<string, unknown>)["tx_count"];
      return typeof n === "number" && Number.isSafeInteger(n) && n >= 0 ? n : 0;
    };
    return txCount(stats) + txCount(mempool) > 0;
  }

  /** Raw transaction hex (verified against the requested txid by the caller). */
  async getTxHex(txidHex: string): Promise<string> {
    txidToBytes(txidHex); // validates format
    const body = await this.request(`/tx/${txidHex}/hex`);
    const hex = body.trim();
    if (!/^[0-9a-f]{20,2000000}$/.test(hex) || hex.length % 2 !== 0) {
      throw new Error("malformed transaction hex");
    }
    return hex;
  }

  async getTxStatus(txidHex: string): Promise<EsploraTxStatus> {
    txidToBytes(txidHex);
    const data = await this.requestJson(`/tx/${txidHex}/status`);
    if (typeof data !== "object" || data === null) throw new Error("malformed status");
    const o = data as Record<string, unknown>;
    const confirmed = o["confirmed"] === true;
    const height = o["block_height"];
    return {
      confirmed,
      // Same bound as parseUtxo: a negative height is not a height.
      blockHeight: typeof height === "number" && Number.isSafeInteger(height) && height >= 0 ? height : null,
    };
  }

  async getFeeEstimates(): Promise<FeeEstimates> {
    const data = await this.requestJson("/fee-estimates");
    if (typeof data !== "object" || data === null) throw new Error("malformed fee estimates");
    const out: FeeEstimates = {};
    for (const [target, rate] of Object.entries(data as Record<string, unknown>)) {
      if (!/^\d{1,4}$/.test(target)) continue;
      if (typeof rate !== "number" || !Number.isFinite(rate) || rate < 0 || rate > 100_000) continue;
      out[target] = rate;
    }
    return out;
  }

  /** Broadcast a signed transaction. Returns the txid reported by the node. */
  async broadcastTx(rawHex: string): Promise<string> {
    if (!/^[0-9a-f]+$/.test(rawHex) || rawHex.length % 2 !== 0 || rawHex.length > 800_000) {
      throw new Error("malformed transaction hex");
    }
    const body = await this.request("/tx", { method: "POST", body: rawHex });
    const txidHex = body.trim();
    txidToBytes(txidHex);
    return txidHex;
  }
}

/**
 * Read a response body with the size cap enforced DURING the read — a hostile
 * server must not be able to balloon memory before a post-hoc length check.
 */
async function readBodyCapped(res: Response, maxBytes: number): Promise<string> {
  const declared = res.headers.get("content-length");
  if (declared && Number(declared) > maxBytes) throw new Error("response too large");
  const reader = res.body?.getReader?.();
  if (!reader) {
    // Environment without streaming (e.g. a test mock) — cap after the fact.
    const body = await res.text();
    if (body.length > maxBytes) throw new Error("response too large");
    return body;
  }
  const chunks: Uint8Array[] = [];
  let received = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    received += value.length;
    if (received > maxBytes) {
      void reader.cancel().catch(() => undefined);
      throw new Error("response too large");
    }
    chunks.push(value);
  }
  const merged = new Uint8Array(received);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.length;
  }
  return new TextDecoder().decode(merged);
}

function assertSaneAddressString(address: string): void {
  if (!/^[a-zA-Z0-9]{14,100}$/.test(address)) throw new Error("malformed address");
}

function parseUtxo(entry: unknown): EsploraUtxo {
  if (typeof entry !== "object" || entry === null) throw new Error("malformed UTXO");
  const o = entry as Record<string, unknown>;
  const txid = o["txid"];
  const vout = o["vout"];
  const value = o["value"];
  if (typeof txid !== "string") throw new Error("malformed UTXO txid");
  txidToBytes(txid);
  if (typeof vout !== "number" || !Number.isSafeInteger(vout) || vout < 0 || vout > 100_000) {
    throw new Error("malformed UTXO vout");
  }
  // The MAX_MONEY ceiling matters: without it a hostile or compromised server
  // can report a single UTXO worth ~90 million BTC. That fabricated coin would
  // be summed into the displayed balance and offered to coin selection; the
  // spend then dead-ends far downstream. Reject it here, where it is a lie.
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || BigInt(value) > MAX_MONEY) {
    throw new Error("malformed UTXO value");
  }
  const status = o["status"];
  let confirmed = false;
  let blockHeight: number | null = null;
  if (typeof status === "object" && status !== null) {
    const s = status as Record<string, unknown>;
    confirmed = s["confirmed"] === true;
    const h = s["block_height"];
    if (typeof h === "number" && Number.isSafeInteger(h) && h >= 0) blockHeight = h;
  }
  return { txid, vout, value: BigInt(value), confirmed, blockHeight };
}
