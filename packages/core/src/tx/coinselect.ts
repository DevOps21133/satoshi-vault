/**
 * Coin selection and fee estimation.
 *
 * Strategies:
 *  - Manual: the user picks UTXOs explicitly (full UTXO control).
 *  - Automatic: branch-and-bound search for a changeless solution (avoids
 *    creating a change output that links coins), falling back to
 *    largest-first accumulation with a change output.
 *
 * All amounts are bigint satoshis. Fees are computed from virtual size
 * (BIP141 weight / 4) using per-type input/output size constants.
 */

import { SpendType } from "./sign.js";

export interface Utxo {
  txid: string; // display order hex
  vout: number;
  value: bigint;
  spendType: SpendType;
  /** Derivation info used later by the PSBT builder. */
  derivationPath: string;
  scriptPubKey: Uint8Array;
}

/** Input vsize contribution (vbytes), including witness discount. */
export const INPUT_VSIZE: Record<SpendType, number> = {
  p2pkh: 148,
  "p2sh-p2wpkh": 91,
  p2wpkh: 68,
  p2tr: 57.5,
};

/** Output vsize contribution by scriptPubKey length: 8 (value) + 1 (len) + script. */
export function outputVsize(scriptPubKeyLength: number): number {
  return 9 + scriptPubKeyLength;
}

/** Tx overhead: version(4) + locktime(4) + in/out counts (~2) + segwit marker/flag (0.5). */
const TX_OVERHEAD_VSIZE = 10.5;

/** Dust thresholds (Bitcoin Core defaults at 3 sat/vB relay). */
export function dustThreshold(spendType: SpendType): bigint {
  return spendType === "p2pkh" ? 546n : 330n;
}

export function estimateVsize(
  inputs: SpendType[],
  outputScriptLengths: number[],
): number {
  let vsize = TX_OVERHEAD_VSIZE;
  for (const t of inputs) vsize += INPUT_VSIZE[t];
  for (const len of outputScriptLengths) vsize += outputVsize(len);
  return Math.ceil(vsize);
}

export function estimateFee(
  inputs: SpendType[],
  outputScriptLengths: number[],
  feeRateSatPerVb: number,
): bigint {
  if (!Number.isFinite(feeRateSatPerVb) || feeRateSatPerVb < 1 || feeRateSatPerVb > 10_000) {
    throw new Error("fee rate out of sane bounds (1..10000 sat/vB)");
  }
  const vsize = estimateVsize(inputs, outputScriptLengths);
  return BigInt(Math.ceil(vsize * feeRateSatPerVb));
}

export interface SelectionTarget {
  /** Amount to the recipient (excluding fee). */
  amount: bigint;
  /** Recipient scriptPubKey length (for fee estimation). */
  recipientScriptLength: number;
  /** Change scriptPubKey length. */
  changeScriptLength: number;
  changeSpendType: SpendType;
  feeRateSatPerVb: number;
}

export interface SelectionResult {
  inputs: Utxo[];
  fee: bigint;
  /** Zero when no change output should be created. */
  change: bigint;
}

/**
 * Branch-and-bound changeless search (bounded), fallback accumulative.
 * Throws if funds are insufficient at the requested fee rate.
 */
export function selectCoins(utxos: Utxo[], target: SelectionTarget): SelectionResult {
  if (target.amount <= 0n) throw new Error("amount must be positive");
  const sorted = [...utxos].sort((a, b) => (b.value > a.value ? 1 : b.value < a.value ? -1 : 0));

  const bnb = branchAndBound(sorted, target);
  if (bnb) return bnb;

  // Accumulative fallback with change.
  const selected: Utxo[] = [];
  let total = 0n;
  for (const utxo of sorted) {
    selected.push(utxo);
    total += utxo.value;
    const feeWithChange = estimateFee(
      selected.map((u) => u.spendType),
      [target.recipientScriptLength, target.changeScriptLength],
      target.feeRateSatPerVb,
    );
    const needed = target.amount + feeWithChange;
    if (total >= needed) {
      const change = total - target.amount - feeWithChange;
      if (change < dustThreshold(target.changeSpendType)) {
        // Change would be dust: fold it into the fee, drop the change output.
        return { inputs: selected, fee: total - target.amount, change: 0n };
      }
      return { inputs: selected, fee: feeWithChange, change };
    }
  }
  throw new Error("insufficient funds for amount + fee");
}

/** Changeless exact-ish match: excess (paid to fee) must stay below this. */
function branchAndBound(sorted: Utxo[], target: SelectionTarget): SelectionResult | null {
  const maxExcess = 1000n; // sat we are willing to burn to avoid a change output
  const types = (sel: Utxo[]) => sel.map((u) => u.spendType);
  let best: Utxo[] | null = null;
  let bestExcess = maxExcess + 1n;
  const maxTries = 50_000;
  let tries = 0;

  const search = (index: number, selected: Utxo[], total: bigint): void => {
    if (tries++ > maxTries || best !== null) return;
    const fee = estimateFee(types(selected), [target.recipientScriptLength], target.feeRateSatPerVb);
    const needed = target.amount + fee;
    if (selected.length > 0 && total >= needed) {
      const excess = total - needed;
      if (excess <= maxExcess && excess < bestExcess) {
        best = [...selected];
        bestExcess = excess;
      }
      return;
    }
    if (index >= sorted.length) return;
    // Remaining value bound.
    let remaining = 0n;
    for (let i = index; i < sorted.length; i++) remaining += sorted[i]!.value;
    if (total + remaining < needed) return;

    search(index + 1, [...selected, sorted[index]!], total + sorted[index]!.value);
    search(index + 1, selected, total);
  };
  search(0, [], 0n);

  if (!best) return null;
  const chosen: Utxo[] = best;
  let total = 0n;
  for (const u of chosen) total += u.value;
  return { inputs: chosen, fee: total - target.amount, change: 0n };
}
