/**
 * Account detail: balance discovery, receive addresses, coin control, and the
 * entry point to Send.
 */

import { amountNode, clear, el, renderQr, toast } from "@satoshivault/ui";
import { WatchAccount } from "@satoshivault/core";
import { AppCtx, View } from "../types";
import { AccountState, discoverAccount } from "../discovery";
import { removeAccount, renameAccount, StoredAccount } from "../store";

export function accountView(app: AppCtx, account: StoredAccount): View {
  const watch = new WatchAccount(account.data);
  const body = el("div", {});
  let alive = true;
  let state: AccountState | null = null;
  const selected = new Set<string>(); // "txid:vout" manual coin control

  const render = () => {
    clear(body);

    // --- header / balance ---
    const balanceCard = el(
      "div",
      { class: "card" },
      el("div", { class: "row spread" },
        el("h2", {}, account.label),
        el("span", { class: "badge orange" }, account.data.network)),
      state
        ? el("div", {},
            el("div", { class: "kv" }, el("span", { class: "k" }, "Balance"),
              el("span", { class: "v" }, amountNode(state.balance))),
            state.balance !== state.confirmedBalance
              ? el("div", { class: "kv" }, el("span", { class: "k" }, "Confirmed"),
                  el("span", { class: "v" }, amountNode(state.confirmedBalance)))
              : null,
            el("div", { class: "kv" }, el("span", { class: "k" }, "Coins"),
              el("span", { class: "v" }, String(state.utxos.length))))
        : el("p", { class: "dim" }, "Refresh to load balance."),
      el("button", { class: "ghost", onclick: () => void refresh() }, "↻ Refresh"),
    );

    // --- receive ---
    const receiveCard = el("div", { class: "card" }, el("h2", {}, "Receive"));
    if (state) {
      const address = watch.addressAt(0, state.nextReceive);
      const canvas = el("canvas", {}) as HTMLCanvasElement;
      void renderQr(canvas, address, 240);
      receiveCard.append(
        el("div", { class: "qr-frame" }, canvas),
        el("div", { class: "addr" }, address),
        el("p", { class: "dim small" },
          `Address #${state.nextReceive} — a fresh address for every payment protects your privacy.`),
        el("button", {
          class: "ghost",
          onclick: () => {
            void navigator.clipboard?.writeText(address).then(
              () => toast("Address copied"),
              () => toast("Copy failed — select it manually"),
            );
          },
        }, "Copy Address"),
      );
    } else {
      receiveCard.append(el("p", { class: "dim" }, "Refresh first to find the next unused address."));
    }

    // --- coins ---
    const coinsCard = el("div", { class: "card" }, el("h2", {}, "Coins (UTXO Control)"));
    if (state && state.utxos.length) {
      for (const u of state.utxos) {
        const key = `${u.txid}:${u.vout}`;
        const box = el("input", { type: "checkbox", ...(selected.has(key) ? { checked: true } : {}) }) as HTMLInputElement;
        box.addEventListener("change", () => {
          if (box.checked) selected.add(key);
          else selected.delete(key);
        });
        coinsCard.append(
          el("label", { class: "row", style: "padding:6px 0; cursor:pointer" },
            box,
            el("div", { style: "flex:1; min-width:0" },
              el("div", { class: "mono small", style: "overflow:hidden; text-overflow:ellipsis; white-space:nowrap" },
                `${u.txid.slice(0, 16)}…:${u.vout}`),
              el("div", { class: "dim small" },
                `${u.change ? "change" : "receive"} #${u.index}${u.confirmed ? "" : " · unconfirmed"}`)),
            amountNode(u.value)),
        );
      }
      coinsCard.append(el("p", { class: "dim small" },
        "Check specific coins to spend ONLY those (manual coin control); leave all unchecked for automatic selection."));
    } else {
      coinsCard.append(el("p", { class: "dim" }, state ? "No coins." : "Refresh to list coins."));
    }

    // --- actions ---
    const sendBtn = el("button", {
      class: "primary",
      onclick: () => {
        if (!state) {
          toast("Refresh first");
          return;
        }
        if (state.utxos.length === 0) {
          toast("Nothing to spend");
          return;
        }
        app.showSend(account, state, selected.size ? new Set(selected) : null);
      },
    }, "Send ₿");

    const renameBtn = el("button", {
      class: "ghost",
      onclick: () => {
        const label = prompt("New account label:", account.label);
        if (label === null) return;
        renameAccount(account.id, label.trim());
        account.label = label.trim() || account.label;
        render();
      },
    }, "Rename");

    const deleteBtn = el("button", {
      class: "danger",
      onclick: () => {
        if (!confirm(`Remove "${account.label}" from this wallet? (The vault and your coins are unaffected.)`)) return;
        removeAccount(account.id);
        toast("Account removed");
        app.show("home");
      },
    }, "Remove Account");

    body.append(
      balanceCard,
      sendBtn,
      receiveCard,
      coinsCard,
      el("div", { class: "row" }, renameBtn, deleteBtn),
      el("button", { class: "ghost", onclick: () => app.show("home") }, "← All Accounts"),
    );
  };

  const refresh = async () => {
    const progress = el("div", { class: "banner good" }, "Connecting…");
    body.prepend(progress);
    try {
      const client = app.client(account.data.network as never);
      state = await discoverAccount(watch, client, (message) => {
        if (alive) progress.textContent = message;
      });
      selected.clear();
      if (alive) render();
    } catch (e) {
      if (alive) {
        progress.remove();
        toast(e instanceof Error ? e.message : "Discovery failed");
      }
    }
  };

  render();
  void refresh();
  return {
    node: body,
    destroy: () => {
      alive = false;
    },
  };
}
