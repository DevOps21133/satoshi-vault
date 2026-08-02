/**
 * Send flow: compose → review → animated PSBT QR to the Signer → scan the
 * signed transaction back → verify byte-for-byte against what was reviewed →
 * broadcast.
 *
 * The QR channel is untrusted in BOTH directions; verifySignedTx() rejects
 * any returned transaction that does not spend/pay exactly what was reviewed.
 */

import {
  AnimatedQr,
  amountNode,
  clear,
  el,
  renderQr,
  ScannerHandle,
  startScanner,
  toast,
} from "@satoshivault/ui";
import {
  bytesToHex,
  ChunkAssembler,
  decodeAddress,
  encodeChunks,
  FrameParseError,
  NETWORKS,
  serializePsbt,
  WatchAccount,
} from "@satoshivault/core";
import { AppCtx, View } from "../types";
import { AccountState } from "../discovery";
import { buildSend, BuiltSend, parseBtcAmount, verifySignedTx } from "../build";
import { loadBook, StoredAccount } from "../store";

export function sendView(
  app: AppCtx,
  account: StoredAccount,
  state: AccountState,
  preselected: Set<string> | null,
): View {
  const watch = new WatchAccount(account.data);
  const network = NETWORKS[account.data.network as keyof typeof NETWORKS];
  const client = app.client(account.data.network as never);
  const body = el("div", {});

  let animator: AnimatedQr | null = null;
  let scanner: ScannerHandle | null = null;
  // Bumped on every destroy so a camera start still in flight is stopped
  // instead of leaking a live camera with no owner.
  let scanGen = 0;
  const destroy = () => {
    scanGen++;
    animator?.stop();
    animator = null;
    scanner?.stop();
    scanner = null;
  };

  // ---------------------------------------------------------------- compose --
  const stepCompose = (feeEstimates: Record<string, number> | null) => {
    destroy();
    const spendable = preselected
      ? state.utxos.filter((u) => preselected.has(`${u.txid}:${u.vout}`))
      : state.utxos;
    const available = spendable.reduce((a, u) => a + u.value, 0n);

    const addressInput = el("input", {
      type: "text", autocomplete: "off", spellcheck: "false",
      placeholder: "Recipient address",
    }) as HTMLInputElement;

    // Address book shortcut (same network only).
    const bookEntries = loadBook().filter((e) => e.network === account.data.network);
    let bookSelect: HTMLSelectElement | null = null;
    if (bookEntries.length) {
      bookSelect = el("select", {}) as HTMLSelectElement;
      bookSelect.append(el("option", { value: "" }, "— address book —"));
      for (const e of bookEntries) bookSelect.append(el("option", { value: e.address }, `${e.label} (${e.address.slice(0, 12)}…)`));
      bookSelect.addEventListener("change", () => {
        if (bookSelect!.value) addressInput.value = bookSelect!.value;
      });
    }

    const amountInput = el("input", {
      type: "text", inputmode: "decimal", autocomplete: "off",
      placeholder: "0.00000000",
    }) as HTMLInputElement;

    // Fee selection: presets from the server estimates, plus a manual rate.
    const feeInput = el("input", {
      type: "number", min: "1", max: "5000", step: "0.1", value: "1",
    }) as HTMLInputElement;
    const presetRow = el("div", { class: "row" });
    if (feeEstimates) {
      const presets: [string, string][] = [["1", "Fast"], ["6", "Normal"], ["144", "Slow"]];
      for (const [target, label] of presets) {
        const rate = feeEstimates[target];
        if (rate === undefined) continue;
        const rounded = Math.max(1, Math.ceil(rate * 10) / 10);
        presetRow.append(el("button", {
          class: "ghost small",
          onclick: () => { feeInput.value = String(rounded); },
        }, `${label} (${rounded} sat/vB)`));
      }
    }

    const rbfBox = el("input", { type: "checkbox", checked: true }) as HTMLInputElement;

    const submit = el("button", {
      class: "primary",
      onclick: () => {
        void (async () => {
          submit.setAttribute("disabled", "");
          submit.textContent = "Building…";
          try {
            // Read the field ONCE: the same string is decoded, built against
            // and shown on the review screen — the input cannot change between
            // validation and display while buildSend awaits the network.
            const addressText = addressInput.value.trim();
            const recipient = decodeAddress(addressText, network);
            const amount = parseBtcAmount(amountInput.value);
            const feeRate = Number(feeInput.value);
            if (!Number.isFinite(feeRate) || feeRate < 1 || feeRate > 5000) {
              throw new Error("fee rate must be between 1 and 5000 sat/vB");
            }
            const built = await buildSend({
              watch,
              utxos: spendable,
              manual: preselected !== null,
              recipient,
              amount,
              feeRateSatPerVb: feeRate,
              rbf: rbfBox.checked,
              changeIndex: state.nextChange,
              client,
            });
            stepReview(built, addressText, amount);
          } catch (e) {
            toast(e instanceof Error ? e.message : "Could not build transaction");
            submit.removeAttribute("disabled");
            submit.textContent = "Review Transaction";
          }
        })();
      },
    }, "Review Transaction");

    clear(body);
    body.append(
      el("div", { class: "card" },
        el("div", { class: "row spread" },
          el("h2", {}, "Send"),
          el("span", { class: "badge orange" }, account.data.network)),
        el("div", { class: "kv" },
          el("span", { class: "k" }, preselected ? "Selected coins" : "Available"),
          el("span", { class: "v" }, amountNode(available))),
        preselected
          ? el("div", { class: "banner good" },
              `Manual coin control: spending only the ${spendable.length} coin(s) you checked.`)
          : null,
        el("label", { class: "field" }, el("span", { class: "cap" }, "Recipient"), addressInput),
        bookSelect ? el("label", { class: "field" }, el("span", { class: "cap" }, "From Address Book"), bookSelect) : null,
        el("label", { class: "field" }, el("span", { class: "cap" }, "Amount (BTC)"), amountInput),
        el("label", { class: "field" }, el("span", { class: "cap" }, "Fee Rate (sat/vB)"), feeInput),
        presetRow,
        el("label", { class: "row", style: "cursor:pointer" }, rbfBox,
          el("span", {}, "Replaceable (RBF) — allows bumping the fee later")),
      ),
      submit,
      el("button", { class: "ghost", onclick: () => app.showAccount(account) }, "Cancel"),
    );
  };

  // ----------------------------------------------------------------- review --
  const stepReview = (built: BuiltSend, recipientAddress: string, amount: bigint) => {
    destroy();
    const inputTotal = built.inputs.reduce((a, u) => a + u.value, 0n);
    const feeRateEff = built.vsize > 0 ? Number(built.fee) / built.vsize : 0;

    clear(body);
    body.append(
      el("div", { class: "card" },
        el("h2", {}, "Review"),
        el("div", { class: "kv" }, el("span", { class: "k" }, "To"), el("span", { class: "v addr" }, recipientAddress)),
        el("div", { class: "kv" }, el("span", { class: "k" }, "Amount"), el("span", { class: "v" }, amountNode(amount))),
        el("div", { class: "kv" }, el("span", { class: "k" }, "Fee"), el("span", { class: "v" }, amountNode(built.fee))),
        el("div", { class: "kv" }, el("span", { class: "k" }, "Fee rate"),
          el("span", { class: "v" }, `≈ ${feeRateEff.toFixed(1)} sat/vB (${built.vsize} vB)`)),
        el("div", { class: "kv" }, el("span", { class: "k" }, "Inputs"),
          el("span", { class: "v" }, `${built.inputs.length} coin(s), `, amountNode(inputTotal))),
        built.change > 0n
          ? el("div", { class: "kv" }, el("span", { class: "k" }, "Change (back to you)"),
              el("span", { class: "v" }, amountNode(built.change)))
          : el("p", { class: "dim small" }, "No change output — the remainder goes to fees (sub-dust)."),
        el("p", { class: "dim small" },
          "The vault will independently verify every amount and the change address. " +
          "ALWAYS confirm the recipient and amount on the vault screen — that display is the trusted one."),
      ),
      el("button", { class: "primary", onclick: () => stepShowPsbt(built) }, "Show QR to Vault"),
      el("button", { class: "ghost", onclick: () => stepCompose(null) }, "← Edit"),
      el("button", { class: "ghost", onclick: () => app.showAccount(account) }, "Cancel"),
    );
  };

  // -------------------------------------------------- animated PSBT display --
  const stepShowPsbt = (built: BuiltSend) => {
    destroy();
    const frames = encodeChunks("PSBT", serializePsbt(built.psbt));
    const canvas = el("canvas", {}) as HTMLCanvasElement;
    const counter = el("div", { class: "dim small center" }, "");

    clear(body);
    body.append(
      el("div", { class: "card center" },
        el("h2", {}, "Scan With the Vault"),
        el("p", {}, "On the Signer: Sign → point its camera at this QR."),
        el("div", { class: "qr-frame" }, canvas),
        counter,
      ),
      el("button", { class: "primary", onclick: () => stepScanSigned(built) }, "Vault Signed — Scan Result"),
      el("button", { class: "ghost", onclick: () => app.showAccount(account) }, "Cancel"),
    );

    animator = new AnimatedQr(canvas, frames, 500);
    animator.start((i, total) => {
      counter.textContent = total > 1 ? `frame ${i + 1} / ${total}` : "";
    });
  };

  // ------------------------------------------------------- scan signed txn --
  const stepScanSigned = (built: BuiltSend) => {
    destroy();
    const assembler = new ChunkAssembler();
    const videoBox = el("div", {});
    const stats = el("div", { class: "dim small center" }, "Waiting for the vault's signed-transaction QR…");
    let finished = false;

    clear(body);
    body.append(
      el("div", { class: "card" },
        el("h2", {}, "Scan Signed Transaction"),
        videoBox,
        stats,
      ),
      el("button", { class: "ghost", onclick: () => stepShowPsbt(built) }, "← Back to QR"),
      el("button", { class: "ghost", onclick: () => app.showAccount(account) }, "Cancel"),
    );

    const gen = scanGen;
    startScanner(videoBox, (text) => {
      if (finished) return;
      try {
        const p = assembler.add(text);
        if (p.total > 0) stats.textContent = `${p.received} / ${p.total} frames`;
      } catch (e) {
        if (e instanceof FrameParseError) return; // stray non-vault QR — ignore
        // Anything else from the assembler is a tampering signal: surface it.
        toast(e instanceof Error ? e.message : "Corrupted transfer — restarting scan");
        assembler.reset();
        stats.textContent = "Transfer rejected — waiting for the vault's signed-transaction QR…";
        return;
      }
      if (assembler.isComplete()) {
        finished = true;
        try {
          const { type, payload } = assembler.assemble();
          if (type !== "TXN") throw new Error(`expected a signed transaction, got ${type}`);
          const { txidHex } = verifySignedTx(payload, built.psbt);
          scanner?.stop();
          scanner = null;
          stepBroadcast(payload, txidHex, built);
        } catch (e) {
          toast(e instanceof Error ? e.message : "Invalid signed transaction");
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
      videoBox.append(el("div", { class: "banner bad" }, "Camera unavailable — scanning requires the camera."));
    });
  };

  // -------------------------------------------------------------- broadcast --
  const stepBroadcast = (raw: Uint8Array, txidHex: string, built: BuiltSend) => {
    destroy();
    const status = el("div", { class: "banner good" }, "Verified against the reviewed transaction ✓");
    const broadcastBtn = el("button", {
      class: "primary",
      onclick: () => {
        void (async () => {
          broadcastBtn.setAttribute("disabled", "");
          broadcastBtn.textContent = "Broadcasting…";
          try {
            const returned = await client.broadcastTx(bytesToHex(raw));
            stepDone(returned);
          } catch (e) {
            status.className = "banner bad";
            status.textContent = e instanceof Error ? `Broadcast failed: ${e.message}` : "Broadcast failed";
            broadcastBtn.removeAttribute("disabled");
            broadcastBtn.textContent = "Retry Broadcast";
          }
        })();
      },
    }, "Broadcast Transaction");

    clear(body);
    body.append(
      el("div", { class: "card" },
        el("h2", {}, "Ready to Broadcast"),
        status,
        el("div", { class: "kv" }, el("span", { class: "k" }, "Txid"), el("span", { class: "v addr" }, txidHex)),
        el("div", { class: "kv" }, el("span", { class: "k" }, "Fee"), el("span", { class: "v" }, amountNode(built.fee))),
      ),
      broadcastBtn,
      el("button", { class: "ghost", onclick: () => app.showAccount(account) }, "Cancel"),
    );
  };

  const stepDone = (txidHex: string) => {
    destroy();
    const canvas = el("canvas", {}) as HTMLCanvasElement;
    void renderQr(canvas, txidHex, 200);
    clear(body);
    body.append(
      el("div", { class: "card center" },
        el("h2", {}, "Broadcast ✓"),
        el("p", {}, "The network accepted the transaction."),
        el("div", { class: "kv" }, el("span", { class: "k" }, "Txid"), el("span", { class: "v addr" }, txidHex)),
        el("div", { class: "qr-frame" }, canvas),
      ),
      el("button", { class: "primary", onclick: () => app.showAccount(account) }, "Done"),
    );
  };

  // Kick off: fetch fee estimates (best-effort), then compose.
  clear(body);
  body.append(el("div", { class: "card" }, el("p", { class: "dim" }, "Loading fee estimates…")));
  void client.getFeeEstimates()
    .then((fees) => stepCompose(fees))
    .catch(() => stepCompose(null));

  return { node: body, destroy };
}
