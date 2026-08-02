/**
 * BIP44 gap-limit address discovery over Esplora, plus the script helpers the
 * PSBT builder shares. All chain data is treated as untrusted: addresses are
 * derived locally from the xpub and only *queried* remotely — the server
 * learns addresses (an accepted watch-only tradeoff, mitigated by running
 * your own node) but can never lie about scripts or keys.
 */

import {
  EsploraClient,
  hash160,
  p2pkhScript,
  p2shP2wpkhRedeemScript,
  p2shScript,
  p2trScript,
  p2wpkhScript,
  taprootOutputKey,
  WatchAccount,
  xOnly,
} from "@satoshivault/core";

export const GAP_LIMIT = 20;
const BATCH = 8;

export interface DiscoveredUtxo {
  txid: string;
  vout: number;
  value: bigint;
  confirmed: boolean;
  address: string;
  change: 0 | 1;
  index: number;
}

export interface AccountState {
  utxos: DiscoveredUtxo[];
  balance: bigint;
  confirmedBalance: bigint;
  /** First unused receive / change indices. */
  nextReceive: number;
  nextChange: number;
  /** Receive addresses with history (for the receive screen). */
  usedReceive: { index: number; address: string }[];
}

/** The scriptPubKey that address (change, index) pays to — derived locally. */
export function scriptPubKeyFor(watch: WatchAccount, change: 0 | 1, index: number): Uint8Array {
  const pubkey = watch.publicKeyAt(change, index);
  switch (watch.scriptType) {
    case "p2pkh":
      return p2pkhScript(hash160(pubkey));
    case "p2sh-p2wpkh":
      return p2shScript(hash160(p2shP2wpkhRedeemScript(pubkey)));
    case "p2wpkh":
      return p2wpkhScript(hash160(pubkey));
    case "p2tr":
      return p2trScript(taprootOutputKey(xOnly(pubkey)));
  }
}

async function scanChain(
  watch: WatchAccount,
  client: EsploraClient,
  change: 0 | 1,
  onProgress: (checked: number) => void,
): Promise<{ used: { index: number; address: string }[]; next: number }> {
  const used: { index: number; address: string }[] = [];
  let next = 0;
  let gap = 0;
  let index = 0;
  let checked = 0;

  while (gap < GAP_LIMIT && index < 100_000) {
    const batch: { index: number; address: string }[] = [];
    for (let i = 0; i < BATCH; i++) batch.push({ index: index + i, address: watch.addressAt(change, index + i) });
    const results = await Promise.all(batch.map((b) => client.addressHasHistory(b.address)));
    for (let i = 0; i < batch.length; i++) {
      checked++;
      if (results[i]) {
        used.push(batch[i]!);
        gap = 0;
        next = batch[i]!.index + 1;
      } else {
        gap++;
        if (gap >= GAP_LIMIT) break;
      }
    }
    index += BATCH;
    onProgress(checked);
  }
  return { used, next };
}

export async function discoverAccount(
  watch: WatchAccount,
  client: EsploraClient,
  onProgress: (message: string) => void,
): Promise<AccountState> {
  onProgress("Scanning receive addresses…");
  const receive = await scanChain(watch, client, 0, (n) => onProgress(`Scanning receive addresses… ${n}`));
  onProgress("Scanning change addresses…");
  const changeChain = await scanChain(watch, client, 1, (n) => onProgress(`Scanning change addresses… ${n}`));

  const utxos: DiscoveredUtxo[] = [];
  const chains: [0 | 1, { index: number; address: string }[]][] = [
    [0, receive.used],
    [1, changeChain.used],
  ];
  let fetched = 0;
  for (const [change, entries] of chains) {
    for (const entry of entries) {
      onProgress(`Fetching coins… ${++fetched}/${receive.used.length + changeChain.used.length}`);
      const list = await client.getAddressUtxos(entry.address);
      for (const u of list) {
        utxos.push({
          txid: u.txid,
          vout: u.vout,
          value: u.value,
          confirmed: u.confirmed,
          address: entry.address,
          change,
          index: entry.index,
        });
      }
    }
  }

  let balance = 0n;
  let confirmedBalance = 0n;
  for (const u of utxos) {
    balance += u.value;
    if (u.confirmed) confirmedBalance += u.value;
  }
  return {
    utxos,
    balance,
    confirmedBalance,
    nextReceive: receive.next,
    nextChange: changeChain.next,
    usedReceive: receive.used,
  };
}
