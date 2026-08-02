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
import { brand, donateFooter, el, mount } from "@satoshivault/ui";
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
/**
 * While the app is off screen nobody is watching the vault, so the countdown
 * collapses to this grace period — long enough to survive an OS permission
 * dialog, short enough that a phone put down face-up locks itself.
 */
const BACKGROUND_LOCK_MS = 30 * 1000;

const root = document.getElementById("app")!;
let session: Session | null = null;
let network: Network = NETWORKS[loadNetworkName()];
let activeView: View | null = null;
let currentName: ViewName = "lock";
let idleTimer: ReturnType<typeof setTimeout> | undefined;
/** Wall-clock instant at which the session must be gone. */
let idleDeadline = 0;

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

// One banner instance for the whole app life. Building a fresh one per
// navigation would register another pair of window listeners every time, and
// those closures (and their nodes) would never be released.
const banner = el("div", { class: "banner bad" },
  "⚠ This device appears to be ONLINE. The Signer is built for an air-gapped device — enable airplane mode.");

function onlineBanner(): HTMLElement {
  banner.style.display = navigator.onLine ? "" : "none";
  return banner;
}

for (const evt of ["online", "offline"] as const) {
  window.addEventListener(evt, () => {
    banner.style.display = navigator.onLine ? "" : "none";
  });
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
    donateFooter(),
    unlocked ? tabs(name) : null,
  );
}

function armIdleLock(): void {
  idleDeadline = Date.now() + IDLE_LOCK_MS;
  scheduleIdleCheck(IDLE_LOCK_MS);
}

function scheduleIdleCheck(ms: number): void {
  if (idleTimer) clearTimeout(idleTimer);
  idleTimer = setTimeout(checkIdle, Math.max(0, ms));
}

/**
 * The lock decision is made against the wall clock, never against "the timer
 * fired". A backgrounded WebView freezes and throttles timers, so a pure
 * setTimeout would silently extend an unlocked session for as long as the app
 * sat in the background.
 */
function checkIdle(): void {
  if (!session) return;
  const remaining = idleDeadline - Date.now();
  if (remaining <= 0) {
    if (currentName !== "lock") app.lockNow();
    return;
  }
  scheduleIdleCheck(remaining);
}

for (const evt of ["pointerdown", "pointermove", "keydown"] as const) {
  window.addEventListener(evt, () => {
    if (session) armIdleLock();
  }, { passive: true });
}

// Leaving the app (task switcher, screen off, another app coming forward)
// starts the short background countdown, and coming back re-checks it against
// the wall clock. Without this, launchMode="singleTask" would resume straight
// into an unlocked vault however long the phone had been out of the user's hands.
document.addEventListener("visibilitychange", () => {
  if (!session) return;
  if (document.visibilityState === "hidden") {
    idleDeadline = Math.min(idleDeadline, Date.now() + BACKGROUND_LOCK_MS);
    scheduleIdleCheck(BACKGROUND_LOCK_MS);
  } else {
    checkIdle();
  }
});

// The page is being torn down or frozen — wipe the key material now.
window.addEventListener("pagehide", () => {
  if (session) app.lockNow();
});

show("lock");
