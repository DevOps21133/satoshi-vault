/**
 * Unsigned-PSBT construction and signed-transaction verification.
 *
 * Security decisions:
 * - Every input embeds the full previous transaction (non_witness_utxo),
 *   verified locally against its txid, ON TOP of witness_utxo for segwit
 *   inputs. The signer cross-checks both, so a lying Esplora server cannot
 *   misrepresent input amounts (the classic fee-attack).
 * - Change outputs carry PSBT_OUT derivation entries so the signer can
 *   cryptographically verify change against its own keys.
 * - The returned signed transaction is verified field-by-field against the
 *   PSBT we sent (same inputs, same outputs, same order) before broadcast —
 *   the QR channel is untrusted in both directions.
 */

import {
  bytesEqual,
  createPsbt,
  decodeAddress,
  DecodedAddress,
  dustThreshold,
  estimateFee,
  estimateVsize,
  EsploraClient,
  hexToBytes,
  parseTx,
  Psbt,
  p2shP2wpkhRedeemScript,
  selectCoins,
  SEQUENCE_FINAL,
  SEQUENCE_RBF,
  setNonWitnessUtxo,
  setOutBip32Derivation,
  setOutTapBip32Derivation,
  setBip32Derivation,
  setRedeemScript,
  setTapBip32Derivation,
  setTapInternalKey,
  setWitnessUtxo,
  Transaction,
  txid,
  txidToBytes,
  Utxo,
  WatchAccount,
  xOnly,
} from "@satoshivault/core";
import { DiscoveredUtxo, scriptPubKeyFor } from "./discovery";

export interface SendRequest {
  watch: WatchAccount;
  /** Candidate coins (auto-selection) or the exact coins (manual). */
  utxos: DiscoveredUtxo[];
  manual: boolean;
  recipient: DecodedAddress;
  amount: bigint;
  feeRateSatPerVb: number;
  rbf: boolean;
  /** First unused change index from discovery. */
  changeIndex: number;
  client: EsploraClient;
}

export interface BuiltSend {
  psbt: Psbt;
  inputs: DiscoveredUtxo[];
  fee: bigint;
  change: bigint;
  vsize: number;
}

function toCoreUtxo(watch: WatchAccount, u: DiscoveredUtxo): Utxo {
  return {
    txid: u.txid,
    vout: u.vout,
    value: u.value,
    spendType: watch.scriptType,
    derivationPath: `${u.change}/${u.index}`,
    scriptPubKey: scriptPubKeyFor(watch, u.change, u.index),
  };
}

export async function buildSend(req: SendRequest): Promise<BuiltSend> {
  const { watch, recipient, amount, feeRateSatPerVb, rbf, client } = req;
  if (amount <= 0n) throw new Error("amount must be positive");
  const changeScript = scriptPubKeyFor(watch, 1, req.changeIndex);

  // --- coin selection --------------------------------------------------------
  let chosen: DiscoveredUtxo[];
  let fee: bigint;
  let change: bigint;
  if (req.manual) {
    chosen = req.utxos;
    if (chosen.length === 0) throw new Error("no coins selected");
    const total = chosen.reduce((a, u) => a + u.value, 0n);
    const types = chosen.map(() => watch.scriptType);
    const feeWithChange = estimateFee(types, [recipient.scriptPubKey.length, changeScript.length], feeRateSatPerVb);
    if (total >= amount + feeWithChange) {
      change = total - amount - feeWithChange;
      fee = feeWithChange;
      if (change < dustThreshold(watch.scriptType)) {
        fee = total - amount;
        change = 0n;
      }
    } else {
      const feeNoChange = estimateFee(types, [recipient.scriptPubKey.length], feeRateSatPerVb);
      if (total < amount + feeNoChange) throw new Error("selected coins do not cover amount + fee");
      fee = total - amount;
      change = 0n;
    }
  } else {
    const result = selectCoins(req.utxos.map((u) => toCoreUtxo(watch, u)), {
      amount,
      recipientScriptLength: recipient.scriptPubKey.length,
      changeScriptLength: changeScript.length,
      changeSpendType: watch.scriptType,
      feeRateSatPerVb,
    });
    fee = result.fee;
    change = result.change;
    chosen = result.inputs.map((core) => {
      const found = req.utxos.find((u) => u.txid === core.txid && u.vout === core.vout);
      if (!found) throw new Error("coin selection returned an unknown coin");
      return found;
    });
  }

  // --- transaction skeleton --------------------------------------------------
  const outputs = [{ value: amount, scriptPubKey: recipient.scriptPubKey }];
  let changePosition = -1;
  if (change > 0n) {
    // CSPRNG coin flip for change position — avoids a change-detection heuristic.
    const flip = new Uint8Array(1);
    globalThis.crypto.getRandomValues(flip);
    changePosition = flip[0]! & 1 ? 1 : 0;
    outputs.splice(changePosition, 0, { value: change, scriptPubKey: changeScript });
  }

  const tx: Transaction = {
    version: 2,
    inputs: chosen.map((u) => ({
      prevTxid: txidToBytes(u.txid),
      prevVout: u.vout,
      scriptSig: new Uint8Array(0),
      sequence: rbf ? SEQUENCE_RBF : SEQUENCE_FINAL,
      witness: [],
    })),
    outputs,
    locktime: 0,
  };
  const psbt = createPsbt(tx);

  // --- input metadata --------------------------------------------------------
  for (let i = 0; i < chosen.length; i++) {
    const u = chosen[i]!;
    const map = psbt.inputMaps[i]!;
    const pubkey = watch.publicKeyAt(u.change, u.index);
    const path = watch.fullPath(u.change, u.index);
    const script = scriptPubKeyFor(watch, u.change, u.index);

    // Full previous transaction, verified against the txid we asked for.
    const rawHex = await client.getTxHex(u.txid);
    const raw = hexToBytes(rawHex);
    const parsed = parseTx(raw);
    if (txid(parsed) !== u.txid) throw new Error("esplora returned a different transaction than requested");
    const prevout = parsed.outputs[u.vout];
    if (!prevout) throw new Error("esplora transaction lacks the referenced output");
    if (prevout.value !== u.value || !bytesEqual(prevout.scriptPubKey, script)) {
      throw new Error("esplora UTXO data contradicts the previous transaction");
    }
    setNonWitnessUtxo(map, raw);

    switch (watch.scriptType) {
      case "p2pkh":
        setBip32Derivation(map, { pubkey, masterFingerprint: watch.masterFingerprint, path });
        break;
      case "p2sh-p2wpkh":
        setWitnessUtxo(map, { value: u.value, scriptPubKey: script });
        setRedeemScript(map, p2shP2wpkhRedeemScript(pubkey));
        setBip32Derivation(map, { pubkey, masterFingerprint: watch.masterFingerprint, path });
        break;
      case "p2wpkh":
        setWitnessUtxo(map, { value: u.value, scriptPubKey: script });
        setBip32Derivation(map, { pubkey, masterFingerprint: watch.masterFingerprint, path });
        break;
      case "p2tr":
        setWitnessUtxo(map, { value: u.value, scriptPubKey: script });
        setTapInternalKey(map, xOnly(pubkey));
        setTapBip32Derivation(map, { pubkey: xOnly(pubkey), masterFingerprint: watch.masterFingerprint, path });
        break;
    }
  }

  // --- change declaration (verified by the signer) ---------------------------
  if (changePosition >= 0) {
    const map = psbt.outputMaps[changePosition]!;
    const changePubkey = watch.publicKeyAt(1, req.changeIndex);
    const changePath = watch.fullPath(1, req.changeIndex);
    if (watch.scriptType === "p2tr") {
      setOutTapBip32Derivation(map, {
        pubkey: xOnly(changePubkey),
        masterFingerprint: watch.masterFingerprint,
        path: changePath,
      });
    } else {
      setOutBip32Derivation(map, {
        pubkey: changePubkey,
        masterFingerprint: watch.masterFingerprint,
        path: changePath,
      });
    }
  }

  const vsize = estimateVsize(
    chosen.map(() => watch.scriptType),
    outputs.map((o) => o.scriptPubKey.length),
  );
  return { psbt, inputs: chosen, fee, change, vsize };
}

/**
 * Verify a signed transaction returned over the QR channel: it must spend
 * exactly the inputs and pay exactly the outputs of the PSBT we generated.
 */
export function verifySignedTx(raw: Uint8Array, psbt: Psbt): { tx: Transaction; txidHex: string } {
  const tx = parseTx(raw);
  const expected = psbt.tx;
  if (tx.inputs.length !== expected.inputs.length) throw new Error("signed tx input count mismatch");
  if (tx.outputs.length !== expected.outputs.length) throw new Error("signed tx output count mismatch");
  for (let i = 0; i < tx.inputs.length; i++) {
    const a = tx.inputs[i]!;
    const b = expected.inputs[i]!;
    if (!bytesEqual(a.prevTxid, b.prevTxid) || a.prevVout !== b.prevVout) {
      throw new Error("signed tx spends different coins than requested");
    }
    if (a.sequence !== b.sequence) {
      throw new Error("signed tx sequence differs from the reviewed transaction (RBF flag tampered)");
    }
  }
  for (let i = 0; i < tx.outputs.length; i++) {
    const a = tx.outputs[i]!;
    const b = expected.outputs[i]!;
    if (a.value !== b.value || !bytesEqual(a.scriptPubKey, b.scriptPubKey)) {
      throw new Error("signed tx outputs differ from the reviewed transaction");
    }
  }
  if (tx.version !== expected.version || tx.locktime !== expected.locktime) {
    throw new Error("signed tx version/locktime differ from the reviewed transaction");
  }
  return { tx, txidHex: txid(tx) };
}

/** Parse a BTC amount string ("0.001") to satoshis, exactly. */
export function parseBtcAmount(text: string): bigint {
  const m = /^(\d{1,8})(?:\.(\d{1,8}))?$/.exec(text.trim());
  if (!m) throw new Error("invalid amount — use BTC with up to 8 decimals");
  const whole = BigInt(m[1]!);
  const frac = BigInt((m[2] ?? "").padEnd(8, "0"));
  const sats = whole * 100_000_000n + frac;
  if (sats <= 0n) throw new Error("amount must be positive");
  return sats;
}
