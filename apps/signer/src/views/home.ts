/**
 * Vault home: identity, and watch-only account export as (animated) QR.
 * Only PUBLIC key material (account xpub + fingerprint + path) ever leaves
 * this screen.
 */

import { AnimatedQr, clear, el, toast } from "@satoshivault/ui";
import {
  accountExportToJson,
  encodeChunks,
  exportAccount,
  SpendType,
} from "@satoshivault/core";
import { AppCtx, View } from "../types";

const SCRIPT_LABELS: [SpendType, string][] = [
  ["p2wpkh", "Native SegWit — BIP84 (recommended)"],
  ["p2tr", "Taproot — BIP86"],
  ["p2sh-p2wpkh", "Nested SegWit — BIP49"],
  ["p2pkh", "Legacy — BIP44"],
];

export function homeView(app: AppCtx): View {
  const session = app.session;
  if (!session) throw new Error("home requires an unlocked session");
  let anim: AnimatedQr | null = null;

  const scriptSel = el("select", {}) as HTMLSelectElement;
  for (const [value, label] of SCRIPT_LABELS) scriptSel.append(el("option", { value }, label));
  const accountIdx = el("input", { type: "number", min: "0", max: "100000", step: "1", value: "0" }) as HTMLInputElement;
  const exportBox = el("div", {});

  const showExport = () => {
    anim?.stop();
    anim = null;
    clear(exportBox);
    const index = parseInt(accountIdx.value, 10);
    if (!Number.isInteger(index) || index < 0 || index > 100_000) {
      toast("Account index out of range");
      return;
    }
    try {
      const data = exportAccount(session.master, scriptSel.value as SpendType, app.network, index);
      const frames = encodeChunks("XPUB", accountExportToJson(data));
      const canvas = el("canvas", {}) as HTMLCanvasElement;
      anim = new AnimatedQr(canvas, frames, 500);
      anim.start();
      exportBox.append(
        el("div", { class: "qr-frame" }, canvas),
        el("div", { class: "kv" }, el("span", { class: "k" }, "Path"), el("span", { class: "v" }, data.path)),
        el("div", { class: "kv" }, el("span", { class: "k" }, "Fingerprint"), el("span", { class: "v" }, data.masterFingerprint)),
        el("div", { class: "kv" }, el("span", { class: "k" }, "Network"), el("span", { class: "v" }, data.network)),
        el("div", { class: "addr" }, data.xpub),
        el("p", { class: "dim small" },
          "Scan this with the Satoshi Vault Wallet app. It contains only public keys — it can watch, never spend."),
      );
    } catch (e) {
      toast(e instanceof Error ? e.message : "Export failed");
    }
  };

  const node = el(
    "div",
    {},
    el(
      "div",
      { class: "card" },
      el("h2", {}, "Vault"),
      el("div", { class: "kv" }, el("span", { class: "k" }, "Master fingerprint"),
        el("span", { class: "v orange" }, session.fingerprint)),
      el("div", { class: "kv" }, el("span", { class: "k" }, "Network"),
        el("span", { class: "v" }, app.network.name)),
      el("div", { class: "kv" }, el("span", { class: "k" }, "Status"),
        el("span", { class: "v" }, el("span", { class: "badge green" }, "offline signer"))),
    ),
    el(
      "div",
      { class: "card" },
      el("h2", {}, "Export Watch-Only Account"),
      el(
        "div",
        { class: "stack" },
        el("label", { class: "field" }, el("span", { class: "cap" }, "Script Type"), scriptSel),
        el("label", { class: "field" }, el("span", { class: "cap" }, "Account Index"), accountIdx),
        el("button", { class: "primary", onclick: showExport }, "Show Export QR"),
      ),
      exportBox,
    ),
  );

  return {
    node,
    destroy: () => {
      anim?.stop();
      anim = null;
    },
  };
}
