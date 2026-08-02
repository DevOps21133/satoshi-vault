/**
 * The project's donation address, shown persistently in both apps.
 *
 * It is a hard-coded constant on purpose: nothing about it is ever fetched,
 * derived, or read from storage, so there is no code path through which a
 * compromised server or a tampered account could swap it for another address.
 */

import { el, toast } from "./dom.js";

/** Bitcoin mainnet, native SegWit (P2WPKH). */
export const DONATION_ADDRESS = "bc1quh3humfcqfh7gh3v8d784e29av24y0vl540qcf";

/**
 * Compact donation footer mounted below every view in both apps. The copy
 * button is best-effort: the Signer runs on an air-gapped device where the
 * clipboard API may be unavailable, so the address is always shown as
 * selectable text too.
 */
export function donateFooter(): HTMLElement {
  const copy = el("button", {
    class: "ghost small",
    onclick: () => {
      const done = () => toast("Donation address copied — thank you! ₿");
      const fallback = () => toast("Could not copy — select the address manually");
      try {
        void navigator.clipboard.writeText(DONATION_ADDRESS).then(done, fallback);
      } catch {
        fallback();
      }
    },
  }, "Copy");

  return el(
    "footer",
    { class: "donate-bar" },
    el("div", { class: "donate-title" }, "₿ Support Satoshi Vault"),
    el("div", { class: "dim small" },
      "Free and open source, no telemetry, no accounts. Donations keep it maintained."),
    el("div", { class: "addr donate-addr" }, DONATION_ADDRESS),
    copy,
  );
}
