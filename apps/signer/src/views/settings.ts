/**
 * Settings: network selection, guarded seed reveal, vault wipe.
 */

import { clear, el, toast } from "@satoshivault/ui";
import { NetworkName, NETWORKS } from "@satoshivault/core";
import { AppCtx, View } from "../types";
import { loadVaultBlob, wipeVault } from "../store";
import { revealWords } from "../session";

export function settingsView(app: AppCtx): View {
  // --- network ---------------------------------------------------------------
  const networkSel = el("select", {}) as HTMLSelectElement;
  for (const name of Object.keys(NETWORKS)) {
    networkSel.append(el("option", { value: name, ...(name === app.network.name ? { selected: true } : {}) }, name));
  }
  networkSel.addEventListener("change", () => {
    app.setNetwork(networkSel.value as NetworkName);
    toast(`Network set to ${networkSel.value}`);
  });

  // --- reveal backup ---------------------------------------------------------
  const revealPw = el("input", { type: "password", autocomplete: "off", placeholder: "Vault password" });
  const revealBox = el("div", {});
  const revealBtn = el("button", { class: "ghost" }, "Reveal Recovery Words") as HTMLButtonElement;
  revealBtn.addEventListener("click", () => {
    void (async () => {
      const blob = loadVaultBlob();
      if (!blob) {
        toast("No vault present");
        return;
      }
      revealBtn.disabled = true;
      revealBtn.textContent = "Deriving key…";
      try {
        await new Promise((r) => setTimeout(r, 30));
        const words = await revealWords(blob, revealPw.value);
        revealPw.value = "";
        clear(revealBox);
        revealBox.append(
          el("div", { class: "banner bad" }, "Anyone seeing these words can take your bitcoin."),
          el("div", { class: "words" },
            ...words.map((w, i) => el("div", { class: "w" }, el("b", {}, String(i + 1)), w))),
          el("button", { class: "ghost", onclick: () => clear(revealBox) }, "Hide"),
        );
      } catch {
        toast("Unable to decrypt — wrong password?");
      } finally {
        revealBtn.disabled = false;
        revealBtn.textContent = "Reveal Recovery Words";
      }
    })();
  });

  // --- wipe ------------------------------------------------------------------
  const wipeConfirm = el("input", { type: "text", autocomplete: "off", placeholder: 'Type "WIPE" to confirm' }) as HTMLInputElement;
  const wipeBtn = el("button", { class: "danger" }, "Wipe Vault From This Device") as HTMLButtonElement;
  wipeBtn.addEventListener("click", () => {
    if (wipeConfirm.value !== "WIPE") {
      toast('Type "WIPE" (uppercase) to confirm');
      return;
    }
    wipeVault();
    toast("Vault wiped");
    app.lockNow();
  });

  const node = el(
    "div",
    {},
    el(
      "div",
      { class: "card" },
      el("h2", {}, "Network"),
      el("p", {}, "Controls which network exported accounts and signed transactions belong to."),
      el("label", { class: "field" }, el("span", { class: "cap" }, "Bitcoin Network"), networkSel),
    ),
    el(
      "div",
      { class: "card" },
      el("h2", {}, "Recovery Backup"),
      el("p", {}, "Re-enter your password to display the seed words for verification against your paper backup."),
      el("div", { class: "stack" },
        el("label", { class: "field" }, el("span", { class: "cap" }, "Password"), revealPw),
        revealBtn),
      revealBox,
    ),
    el(
      "div",
      { class: "card" },
      el("h2", {}, "Danger Zone"),
      el("p", {}, "Removes the encrypted vault from this device. Your bitcoin is only recoverable with the paper backup."),
      el("div", { class: "stack" }, wipeConfirm, wipeBtn),
    ),
    el(
      "div",
      { class: "card" },
      el("h2", {}, "About"),
      el("div", { class: "kv" }, el("span", { class: "k" }, "App"), el("span", { class: "v" }, "Satoshi Vault Signer")),
      el("div", { class: "kv" }, el("span", { class: "k" }, "Telemetry"), el("span", { class: "v" }, "none — ever")),
      el("div", { class: "kv" }, el("span", { class: "k" }, "Network access"),
        el("span", { class: "v" }, "blocked by CSP (connect-src 'none')")),
    ),
  );
  return { node };
}
