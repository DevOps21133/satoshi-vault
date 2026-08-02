/**
 * Tiny DOM helpers. All user-controlled strings go through textContent —
 * innerHTML is never used with dynamic data (XSS is a wallet-drainer here).
 */

export type Child = Node | string | null | undefined;

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Record<string, string | boolean | ((ev: Event) => void)> = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (typeof value === "function") {
      node.addEventListener(key.replace(/^on/, ""), value);
    } else if (typeof value === "boolean") {
      if (value) node.setAttribute(key, "");
    } else {
      node.setAttribute(key, value);
    }
  }
  for (const child of children) {
    if (child === null || child === undefined) continue;
    node.append(typeof child === "string" ? document.createTextNode(child) : child);
  }
  return node;
}

export function clear(node: HTMLElement): void {
  while (node.firstChild) node.removeChild(node.firstChild);
}

export function mount(root: HTMLElement, ...children: Child[]): void {
  clear(root);
  for (const child of children) {
    if (child) root.append(typeof child === "string" ? document.createTextNode(child) : child);
  }
  window.scrollTo(0, 0);
}

let toastTimer: ReturnType<typeof setTimeout> | undefined;

export function toast(message: string, ms = 2600): void {
  let node = document.getElementById("toast");
  if (!node) {
    node = document.createElement("div");
    node.id = "toast";
    document.body.append(node);
  }
  node.textContent = message;
  node.classList.add("show");
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => node!.classList.remove("show"), ms);
}

/** The big ₿ brand header. */
export function brand(subtitle: string): HTMLElement {
  return el(
    "div",
    { class: "brand" },
    el("div", { class: "coin" }, "₿"),
    el("h1", {}, el("span", { class: "accent" }, "SATOSHI"), " VAULT"),
    el("div", { class: "tagline" }, subtitle),
  );
}

/** Format satoshis as "₿ 0.001 234 56" plus sat detail. */
export function formatBtc(sats: bigint): string {
  const negative = sats < 0n;
  const abs = negative ? -sats : sats;
  const whole = abs / 100_000_000n;
  const frac = (abs % 100_000_000n).toString().padStart(8, "0");
  const fracGrouped = `${frac.slice(0, 2)} ${frac.slice(2, 5)} ${frac.slice(5)}`;
  return `${negative ? "-" : ""}${whole}.${fracGrouped}`;
}

export function formatSats(sats: bigint): string {
  return sats.toLocaleString("en-US").replace(/,/g, " ");
}

export function amountNode(sats: bigint): HTMLElement {
  return el(
    "span",
    { class: "amount" },
    el("span", { class: "btc-sign" }, "₿ "),
    formatBtc(sats),
    el("span", { class: "dim small" }, ` (${formatSats(sats)} sat)`),
  );
}
