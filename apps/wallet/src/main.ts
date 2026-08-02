/**
 * Satoshi Vault Wallet — watch-only app shell and router.
 *
 * This app never touches private keys. It watches accounts exported from the
 * Signer, builds unsigned PSBTs, exchanges them with the vault over QR, and
 * broadcasts the verified result. Views owning cameras/timers expose
 * destroy() and the router always calls it before mounting the next view.
 */

import "@satoshivault/ui/theme.css";
import { brand, el, mount } from "@satoshivault/ui";
import { EsploraClient, NetworkName } from "@satoshivault/core";
import { AppCtx, View } from "./types";
import { esploraUrl, StoredAccount } from "./store";
import { AccountState } from "./discovery";
import { homeView } from "./views/home";
import { addView } from "./views/add";
import { accountView } from "./views/account";
import { sendView } from "./views/send";
import { bookView } from "./views/book";
import { settingsView } from "./views/settings";

type TabName = "home" | "book" | "settings";

const root = document.getElementById("app")!;
let activeView: View | null = null;
let activeTab: TabName = "home";

const app: AppCtx = {
  show(view: TabName) {
    activeTab = view;
    switch (view) {
      case "home":
        present(homeView(app));
        break;
      case "book":
        present(bookView(app));
        break;
      case "settings":
        present(settingsView(app));
        break;
    }
  },
  showAdd() {
    activeTab = "home";
    present(addView(app));
  },
  showAccount(account: StoredAccount) {
    activeTab = "home";
    present(accountView(app, account));
  },
  showSend(account: StoredAccount, state: AccountState, preselected: Set<string> | null) {
    activeTab = "home";
    present(sendView(app, account, state, preselected));
  },
  client(network: NetworkName): EsploraClient {
    return new EsploraClient(esploraUrl(network));
  },
};

function tabs(): HTMLElement {
  const tab = (name: TabName, label: string) =>
    el("button", { class: activeTab === name ? "active" : "", onclick: () => app.show(name) }, label);
  return el(
    "nav",
    { class: "tabs" },
    tab("home", "◈ Accounts"),
    tab("book", "☰ Book"),
    tab("settings", "⚙ Settings"),
  );
}

function present(view: View): void {
  activeView?.destroy?.();
  activeView = view;
  mount(root, brand("Wallet · Watch-Only"), view.node, tabs());
}

app.show("home");
