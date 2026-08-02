/**
 * Satoshi Vault Signer — app shell and router.
 *
 * Security posture of the shell:
 * - connect-src 'none' CSP (index.html): no network I/O is possible.
 * - Online detection banner: warns if the host device is not air-gapped.
 * - Idle auto-lock: master key material is wiped after inactivity.
 * - Views owning cameras/mics/timers expose destroy() and the router always
 *   calls it before mounting the next view.
 */

import "@satoshivault/ui/theme.css";
import { brand, el, mount } from "@satoshivault/ui";
import { NETWORKS, NetworkName, Network } from "@satoshivault/core";
import { AppCtx, View, ViewName } from "./types";
import { Session, lock } from "./session";
import { loadNetworkName, saveNetworkName } from "./store";
import { lockView } from "./views/lock";
import { createView } from "./views/create";
import { importView } from "./views/import";
import { homeView } from "./views/home";
import { signView } from "./views/sign";
import { settingsView } from "./views/settings";

const IDLE_LOCK_MS = 10 * 60 * 1000;

const root = document.getElementById("app")!;
let session: Session | null = null;
let network: Network = NETWORKS[loadNetworkName()];
let activeView: View | null = null;
let currentName: ViewName = "lock";
let idleTimer: ReturnType<typeof setTimeout> | undefined;

const app: AppCtx = {
  get network() {
    return network;
  },
  get session() {
    return session;
  },
  show,
  setNetwork(name: NetworkName) {
    network = NETWORKS[name];
    saveNetworkName(name);
  },
  setSession(s: Session) {
    session = s;
    armIdleLock();
  },
  lockNow() {
    if (session) {
      lock(session);
      session = null;
    }
    show("lock");
  },
};

function onlineBanner(): HTMLElement {
  const banner = el("div", { class: "banner bad" },
    "⚠ This device appears to be ONLINE. The Signer is built for an air-gapped device — enable airplane mode.");
  const update = () => {
    banner.style.display = navigator.onLine ? "" : "none";
  };
  window.addEventListener("online", update);
  window.addEventListener("offline", update);
  update();
  return banner;
}

function tabs(active: ViewName): HTMLElement {
  const tab = (name: ViewName, label: string) =>
    el("button", { class: active === name ? "active" : "", onclick: () => show(name) }, label);
  return el(
    "nav",
    { class: "tabs" },
    tab("home", "◈ Vault"),
    tab("sign", "✎ Sign"),
    tab("settings", "⚙ Settings"),
    el("button", { onclick: () => app.lockNow() }, "🔒 Lock"),
  );
}

function buildView(name: ViewName): View {
  switch (name) {
    case "lock":
      return lockView(app);
    case "create":
      return createView(app);
    case "import":
      return importView(app);
    case "home":
      return homeView(app);
    case "sign":
      return signView(app);
    case "settings":
      return settingsView(app);
  }
}

function show(name: ViewName): void {
  // Any unlocked-only view falls back to the lock screen without a session.
  if ((name === "home" || name === "sign" || name === "settings") && !session) name = "lock";
  activeView?.destroy?.();
  currentName = name;
  const view = buildView(name);
  activeView = view;
  const unlocked = session !== null;
  mount(
    root,
    brand(unlocked ? "Signer · Cold Vault" : "Cold Vault Signer"),
    onlineBanner(),
    view.node,
    unlocked ? tabs(name) : null,
  );
}

function armIdleLock(): void {
  if (idleTimer) clearTimeout(idleTimer);
  idleTimer = setTimeout(() => {
    if (session && currentName !== "lock") app.lockNow();
  }, IDLE_LOCK_MS);
}

for (const evt of ["pointerdown", "pointermove", "keydown"] as const) {
  window.addEventListener(evt, () => {
    if (session) armIdleLock();
  }, { passive: true });
}

show("lock");
