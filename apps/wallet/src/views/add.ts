/**
 * Import a watch-only account by scanning the Signer's XPUB QR.
 * The payload is hostile input: parsed strictly, then fully validated by the
 * WatchAccount constructor (rejects private keys, wrong versions, bad paths).
 */

import { clear, el, startScanner, toast, ScannerHandle } from "@satoshivault/ui";
import { accountExportFromJson, AccountExport, ChunkAssembler, WatchAccount } from "@satoshivault/core";
import { AppCtx, View } from "../types";
import { addAccount } from "../store";

export function addView(app: AppCtx): View {
  const body = el("div", {});
  let scanner: ScannerHandle | null = null;

  const destroy = () => {
    scanner?.stop();
    scanner = null;
  };

  const stepScan = () => {
    destroy();
    const assembler = new ChunkAssembler();
    const videoBox = el("div", {});
    const stats = el("div", { class: "dim small center" }, "Waiting for the Signer's export QR…");
    let finished = false;

    clear(body);
    body.append(
      el(
        "div",
        { class: "card" },
        el("h2", {}, "Scan Account Export"),
        el("p", {}, "On the Signer: Vault → Export Watch-Only Account. Point this camera at the QR."),
        videoBox,
        stats,
      ),
      el("button", { class: "ghost", onclick: () => app.show("home") }, "Cancel"),
    );

    startScanner(videoBox, (text) => {
      if (finished) return;
      try {
        const p = assembler.add(text);
        if (p.total > 0) stats.textContent = `${p.received} / ${p.total} frames`;
      } catch {
        return;
      }
      if (assembler.isComplete()) {
        finished = true;
        try {
          const { type, payload } = assembler.assemble();
          if (type !== "XPUB") throw new Error(`expected an account export, got ${type}`);
          const data = accountExportFromJson(payload);
          new WatchAccount(data); // full hostile validation — throws on anything off
          scanner?.stop();
          scanner = null;
          stepLabel(data);
        } catch (e) {
          toast(e instanceof Error ? e.message : "Invalid export");
          assembler.reset();
          finished = false;
        }
      }
    }).then((h) => {
      scanner = h;
    }).catch(() => {
      clear(videoBox);
      videoBox.append(el("div", { class: "banner bad" }, "Camera unavailable — importing requires the camera."));
    });
  };

  const stepLabel = (data: AccountExport) => {
    const label = el("input", { type: "text", autocomplete: "off", placeholder: "e.g. Savings", maxlength: "60" }) as HTMLInputElement;
    clear(body);
    body.append(
      el(
        "div",
        { class: "card" },
        el("h2", {}, "Account Verified"),
        el("div", { class: "kv" }, el("span", { class: "k" }, "Network"), el("span", { class: "v" }, data.network)),
        el("div", { class: "kv" }, el("span", { class: "k" }, "Path"), el("span", { class: "v" }, data.path)),
        el("div", { class: "kv" }, el("span", { class: "k" }, "Vault"), el("span", { class: "v" }, data.masterFingerprint)),
        el("div", { class: "addr" }, data.xpub),
        el("label", { class: "field" }, el("span", { class: "cap" }, "Account Label"), label),
      ),
      el("button", {
        class: "primary",
        onclick: () => {
          try {
            const account = addAccount(label.value.trim(), data);
            toast("Account added");
            app.showAccount(account);
          } catch (e) {
            toast(e instanceof Error ? e.message : "Could not add account");
          }
        },
      }, "Add Account"),
      el("button", { class: "ghost", onclick: () => app.show("home") }, "Cancel"),
    );
  };

  stepScan();
  return { node: body, destroy };
}
