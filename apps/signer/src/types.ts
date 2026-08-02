import { Network, NetworkName } from "@satoshivault/core";
import { Session } from "./session";

export type ViewName = "lock" | "create" | "import" | "home" | "sign" | "settings";

/** A mounted view. destroy() must release cameras/mics/timers. */
export interface View {
  node: HTMLElement;
  destroy?: () => void;
}

export interface AppCtx {
  readonly network: Network;
  readonly session: Session | null;
  show(view: ViewName): void;
  setNetwork(name: NetworkName): void;
  setSession(session: Session): void;
  /** Wipe key material and return to the lock screen. */
  lockNow(): void;
}
