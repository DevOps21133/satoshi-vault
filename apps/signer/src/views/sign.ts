/**
 * PSBT signing over the air gap:
 *   scan animated QR → reassemble → parse → HUMAN REVIEW → sign → show result QR.
 *
 * The review screen is the last line of defense: every input amount, every
 * destination, the change detection and the exact fee are computed locally
 * from the PSBT before a single signature exists. signPsbt() then re-enforces
 * the path policy, prevout binding and sighash allow-list independently.
 */

import { AnimatedQr, amountNode, clear, el, startScanner, toast, ScannerHandle } from "@satoshivault/ui";
import {
  bytesEqual,
  ChunkAssembler,
  classifyInput,
  encodeChunks,
  extractTx,
  finalizePsbt,
  FrameParseError,
  getBip32Derivations,
  getOutBip32Derivations,
  getOutTapBip32Derivations,
  getTapBip32Derivations,
  hash160,
  HDPrivateKey,
  Network,
  p2pkhScript,
  p2shP2wpkhRedeemScript,
  p2shScript,
  p2trScript,
  p2wpkhScript,
  parsePsbt,
  Psbt,
  psbtFee,
  scriptToAddress,
  serializePsbt,
  serializeTx,
  signPsbt,
  SPEND_TYPE_BY_PURPOSE,
  taprootOutputKey,
  txid,
  validateSigningPath,
  xOnly,
  HARDENED_OFFSET,
} from "@satoshivault/core";
import { AppCtx, View } from "../types";

export function signView(app: AppCtx): View {
  const session = app.session;
  if (!session) throw new Error("signing requires an unlocked session");
  const body = el("div", {});
  let scanner: ScannerHandle | null = null;
  let anim: AnimatedQr | null = null;
  // Bumped on every destroy so a camera start still in flight (getUserMedia
  // awaits) is stopped instead of leaking a live camera with no owner.
  let scanGen = 0;

  const destroy = () => {
    scanGen++;
    scanner?.stop();
    scanner = null;
    anim?.stop();
    anim = null;
  };

  // --- step 1: scan the unsigned PSBT ---------------------------------------
  const stepScan = () => {
    destroy();
    const assembler = new ChunkAssembler();
    const videoBox = el("div", {});
    const fill = el("div", { class: "fill" });
    const stats = el("div", { class: "dim small center" }, "Waiting for frames…");
    let finished = false;

    clear(body);
    body.append(
      el(
        "div",
        { class: "card" },
        el("h2", {}, "Scan Transaction"),
        el("p", {}, "Point the camera at the animated QR shown by the Wallet app."),
        videoBox,
        el("div", { class: "meter" }, fill),
        stats,
      ),
      el("button", { class: "ghost", onclick: () => app.show("home") }, "Cancel"),
    );

    const gen = scanGen;
    startScanner(videoBox, (text) => {
      if (finished) return;
      try {
        const progress = assembler.add(text);
        if (progress.total > 0) {
          fill.style.width = `${Math.round(progress.ratio * 100)}%`;
          stats.textContent = `${progress.received} / ${progress.total} frames · ${progress.type}`;
        }
      } catch (e) {
        if (e instanceof FrameParseError) return; // stray non-vault QR — ignore
        // Anything else from the assembler is a tampering signal: surface it.
        toast(e instanceof Error ? e.message : "Corrupted transfer — restarting scan");
        assembler.reset();
        fill.style.width = "0%";
        stats.textContent = "Transfer rejected — waiting for frames…";
        return;
      }
      if (assembler.isComplete()) {
        finished = true;
        try {
          const { type, payload } = assembler.assemble();
          if (type !== "PSBT") throw new Error(`expected a PSBT transfer, got ${type}`);
          const psbt = parsePsbt(payload);
          scanner?.stop();
          scanner = null;
          stepReview(psbt);
        } catch (e) {
          toast(e instanceof Error ? e.message : "Invalid transfer");
          assembler.reset();
          finished = false;
        }
      }
    }).then((h) => {
      if (gen !== scanGen) {
        h.stop(); // view left while the camera was starting — release it
        return;
      }
      scanner = h;
    }).catch(() => {
      clear(videoBox);
      videoBox.append(el("div", { class: "banner bad" }, "Camera unavailable — signing requires the camera."));
    });
  };

  // --- step 2: human review --------------------------------------------------
  const stepReview = (psbt: Psbt) => {
    let fee: bigint;
    let inputs: { index: number; amount: bigint; spendType: string; address: string | null }[];
    try {
      fee = psbtFee(psbt);
      inputs = psbt.tx.inputs.map((_, i) => {
        const c = classifyInput(psbt, i);
        return {
          index: i,
          amount: c.prevout.value,
          spendType: c.spendType,
          address: scriptToAddress(c.prevout.scriptPubKey, app.network),
        };
      });
    } catch (e) {
      toast(e instanceof Error ? e.message : "PSBT rejected");
      stepScan();
      return;
    }

    const totalIn = inputs.reduce((a, x) => a + x.amount, 0n);
    const ownedAccounts = ownedAccountTuples(psbt, session.master, app.network);
    const outputs = psbt.tx.outputs.map((out, i) => ({
      address: scriptToAddress(out.scriptPubKey, app.network),
      amount: out.value,
      change: classifyOutput(psbt, i, session.master, app.network, ownedAccounts),
    }));
    const sendTotal = outputs.filter((o) => o.change.status !== "verified").reduce((a, o) => a + o.amount, 0n);
    const hasMismatch = outputs.some((o) => o.change.status === "mismatch");

    clear(body);
    body.append(
      el(
        "div",
        { class: "card" },
        el("h2", {}, "Review Before Signing"),
        el("div", { class: "banner warn" },
          "Verify every address and amount against what you intended in the Wallet app. " +
          "If anything differs, reject."),
        hasMismatch
          ? el("div", { class: "banner bad" },
              "⚠ An output CLAIMS to be change but does NOT match this vault's keys. " +
              "It is shown as a normal payment below — if you did not add that recipient, reject.")
          : null,
        ...outputs.map((o) =>
          el(
            "div",
            {},
            el("div", { class: "row spread" },
              el("span", { class: "dim small" },
                o.change.status === "verified"
                  ? `Change (verified: returns to this vault at ${o.change.path})`
                  : "Pays to"),
              o.change.status === "verified" ? el("span", { class: "badge orange" }, "change ✓") : null,
              o.change.status === "mismatch" ? el("span", { class: "badge red" }, "fake change") : null),
            el("div", { class: "addr" }, o.address ?? "(non-standard script)"),
            el("div", { class: "kv" }, el("span", { class: "k" }, "Amount"), el("span", { class: "v" }, amountNode(o.amount))),
          )),
        el("hr", { class: "sep" }),
        el("div", { class: "kv" }, el("span", { class: "k" }, "Inputs"),
          el("span", { class: "v" }, `${inputs.length} (${inputs.map((x) => x.spendType).join(", ")})`)),
        el("div", { class: "kv" }, el("span", { class: "k" }, "Total in"), el("span", { class: "v" }, amountNode(totalIn))),
        el("div", { class: "kv" }, el("span", { class: "k" }, "Sending"), el("span", { class: "v" }, amountNode(sendTotal))),
        el("div", { class: "kv" }, el("span", { class: "k" }, "Network fee"), el("span", { class: "v" }, amountNode(fee))),
        el("div", { class: "kv" }, el("span", { class: "k" }, "Network"), el("span", { class: "v" }, app.network.name)),
      ),
      el("button", { class: "primary", onclick: () => stepSign(psbt) }, "Sign Transaction"),
      el("button", { class: "danger", onclick: () => { toast("Rejected — nothing was signed"); app.show("home"); } }, "Reject"),
    );
  };

  // --- step 3: sign and present the result -----------------------------------
  const stepSign = (psbt: Psbt) => {
    let frames: string[];
    let summary: HTMLElement;
    try {
      const result = signPsbt(psbt, session.master, app.network);
      if (result.signedInputs.length === 0) {
        throw new Error("This vault owns none of the inputs — nothing was signed");
      }
      if (result.signedInputs.length === psbt.tx.inputs.length) {
        finalizePsbt(psbt);
        const tx = extractTx(psbt);
        const raw = serializeTx(tx);
        frames = encodeChunks("TXN", raw);
        summary = el(
          "div",
          {},
          el("div", { class: "kv" }, el("span", { class: "k" }, "Txid"), el("span", { class: "v" }, txid(tx))),
          el("div", { class: "kv" }, el("span", { class: "k" }, "Fee"), el("span", { class: "v" }, amountNode(result.fee))),
          el("div", { class: "kv" }, el("span", { class: "k" }, "Size"), el("span", { class: "v" }, `${raw.length} bytes`)),
        );
      } else {
        // Not all inputs are ours — hand back a partially signed PSBT.
        frames = encodeChunks("PSBT", serializePsbt(psbt));
        summary = el("div", { class: "banner warn" },
          `Signed ${result.signedInputs.length} of ${psbt.tx.inputs.length} inputs — returning a partially signed PSBT.`);
      }
    } catch (e) {
      toast(e instanceof Error ? e.message : "Signing refused");
      app.show("home");
      return;
    }

    const canvas = el("canvas", {}) as HTMLCanvasElement;
    anim = new AnimatedQr(canvas, frames, 350);
    const frameLabel = el("div", { class: "dim small center" }, frames.length > 1 ? `1 / ${frames.length}` : "");
    anim.start((i, total) => {
      if (total > 1) frameLabel.textContent = `${i + 1} / ${total}`;
    });

    clear(body);
    body.append(
      el(
        "div",
        { class: "card" },
        el("h2", {}, "Signed — Scan With Wallet"),
        el("div", { class: "qr-frame" }, canvas),
        frameLabel,
        summary,
        el("p", { class: "dim small" }, "The Wallet app verifies and broadcasts. This device stays offline."),
      ),
      el("button", { class: "primary", onclick: () => app.show("home") }, "Done"),
    );
  };

  stepScan();
  return { node: body, destroy };
}

type SpendType = "p2pkh" | "p2sh-p2wpkh" | "p2wpkh" | "p2tr";

type ChangeStatus =
  | { status: "verified"; path: string }
  | { status: "mismatch" }
  | { status: "foreign" };

/** The standard output script this spend type pays to for a given pubkey. */
function scriptForKey(spendType: SpendType, pubkey: Uint8Array): Uint8Array {
  switch (spendType) {
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

/** Derive the pubkey at an absolute path, wiping every intermediate node even on error. */
function derivePubkey(master: HDPrivateKey, path: number[]): Uint8Array {
  let node = master;
  try {
    for (const index of path) {
      const next = node.deriveChild(index);
      if (node !== master) node.wipe();
      node = next;
    }
    return node.publicKey;
  } finally {
    if (node !== master) node.wipe();
  }
}

function formatPath(path: number[]): string {
  return "m/" + path.map((i) => (i >= HARDENED_OFFSET ? `${i - HARDENED_OFFSET}'` : `${i}`)).join("/");
}

/**
 * Account tuples (purpose'/coin'/account') PROVEN to belong to this vault in
 * this transaction: an input counts only when its derivation entry re-derives
 * to a key that the input's prevout script actually pays. Change claims must
 * land in one of these accounts — otherwise a PSBT author who merely knows the
 * (public) fingerprint could steer "change" into an account the wallet is not
 * watching, making the funds invisible to the user.
 */
function ownedAccountTuples(psbt: Psbt, master: HDPrivateKey, network: Network): Set<string> {
  const tuples = new Set<string>();
  for (let i = 0; i < psbt.tx.inputs.length; i++) {
    const map = psbt.inputMaps[i];
    if (!map) continue;
    try {
      const { prevout, spendType } = classifyInput(psbt, i);
      const derivations = spendType === "p2tr" ? getTapBip32Derivations(map) : getBip32Derivations(map);
      for (const d of derivations) {
        if (d.masterFingerprint !== master.fingerprint || d.path.length !== 5) continue;
        try {
          validateSigningPath(d.path, spendType, network);
          const pubkey = derivePubkey(master, d.path);
          if (bytesEqual(scriptForKey(spendType, pubkey), prevout.scriptPubKey)) {
            tuples.add(d.path.slice(0, 3).join("/"));
          }
        } catch {
          continue; // an unprovable claim contributes nothing
        }
      }
    } catch {
      continue; // unclassifiable input — cannot prove ownership from it
    }
  }
  return tuples;
}

/**
 * Change verification. A fingerprint is PUBLIC information, so a derivation
 * entry claiming "this output is your change" is never trusted on its own:
 * the signer re-derives the key at the claimed path (under the wallet path
 * policy), checks that the output script really pays to it, AND requires the
 * claimed account to be one the transaction provably spends from.
 *
 * - "verified": derivation matches our keys in a spending account — genuine change.
 * - "mismatch": claims our fingerprint but fails any check — hostile, surfaced loudly.
 * - "foreign":  no claim about our keys — a normal payment output.
 *
 * The whole classification runs inside try/catch: a malformed output map that
 * makes any parser throw is treated as hostile ("mismatch"), never a crash.
 */
function classifyOutput(
  psbt: Psbt,
  outputIndex: number,
  master: HDPrivateKey,
  network: Network,
  ownedAccounts: Set<string>,
): ChangeStatus {
  const map = psbt.outputMaps[outputIndex];
  const out = psbt.tx.outputs[outputIndex];
  if (!map || !out) return { status: "foreign" };
  let claims;
  try {
    claims = [...getOutBip32Derivations(map), ...getOutTapBip32Derivations(map)].filter(
      (d) => d.masterFingerprint === master.fingerprint,
    );
  } catch {
    return { status: "mismatch" }; // malformed derivation entries are hostile input
  }
  if (claims.length === 0) return { status: "foreign" };

  let verifiedPath: string | null = null;
  for (const claim of claims) {
    try {
      if (claim.path.length !== 5) return { status: "mismatch" };
      const purpose = claim.path[0]! - HARDENED_OFFSET;
      const spendType = SPEND_TYPE_BY_PURPOSE[purpose];
      if (!spendType) return { status: "mismatch" };
      validateSigningPath(claim.path, spendType, network);
      if (!ownedAccounts.has(claim.path.slice(0, 3).join("/"))) return { status: "mismatch" };
      const pubkey = derivePubkey(master, claim.path);
      if (!bytesEqual(scriptForKey(spendType, pubkey), out.scriptPubKey)) return { status: "mismatch" };
      verifiedPath = formatPath(claim.path);
    } catch {
      return { status: "mismatch" };
    }
  }
  return verifiedPath ? { status: "verified", path: verifiedPath } : { status: "foreign" };
}
