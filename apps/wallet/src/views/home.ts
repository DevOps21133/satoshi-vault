/** Account list. */

import { el } from "@satoshivault/ui";
import { AppCtx, View } from "../types";
import { loadAccounts } from "../store";

const TYPE_LABEL: Record<string, string> = {
  p2wpkh: "Native SegWit",
  p2tr: "Taproot",
  "p2sh-p2wpkh": "Nested SegWit",
  p2pkh: "Legacy",
};

export function homeView(app: AppCtx): View {
  const accounts = loadAccounts();

  const list = accounts.length
    ? accounts.map((a) =>
        el(
          "div",
          { class: "card", style: "cursor:pointer", onclick: () => app.showAccount(a) },
          el("div", { class: "row spread" },
            el("h2", {}, a.label),
            el("span", { class: "badge orange" }, a.data.network)),
          el("div", { class: "kv" }, el("span", { class: "k" }, "Type"),
            el("span", { class: "v" }, TYPE_LABEL[a.data.scriptType] ?? a.data.scriptType)),
          el("div", { class: "kv" }, el("span", { class: "k" }, "Path"), el("span", { class: "v" }, a.data.path)),
          el("div", { class: "kv" }, el("span", { class: "k" }, "Vault"), el("span", { class: "v" }, a.data.masterFingerprint)),
        ))
    : [
        el(
          "div",
          { class: "card" },
          el("h2", {}, "Watch-Only Wallet"),
          el("p", {}, "This app holds no keys — it watches accounts exported from your Satoshi Vault Signer, " +
            "builds transactions, and broadcasts them after the vault signs over QR."),
          el("p", { class: "dim small" }, "On the Signer: Vault → Export Watch-Only Account → scan it here."),
        ),
      ];

  const node = el(
    "div",
    {},
    ...list,
    el("button", { class: "primary", onclick: () => app.showAdd() }, "＋ Add Account From Signer"),
  );
  return { node };
}
