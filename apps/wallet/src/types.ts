import { EsploraClient, NetworkName } from "@satoshivault/core";
import { AccountState } from "./discovery";
import { StoredAccount } from "./store";

/** A mounted view. destroy() must release cameras/timers. */
export interface View {
  node: HTMLElement;
  destroy?: () => void;
}

export interface AppCtx {
  show(view: "home" | "book" | "settings"): void;
  showAdd(): void;
  showAccount(account: StoredAccount): void;
  showSend(account: StoredAccount, state: AccountState, preselected: Set<string> | null): void;
  client(network: NetworkName): EsploraClient;
}
