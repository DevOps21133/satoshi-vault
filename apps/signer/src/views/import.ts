/**
 * Import an existing BIP39 mnemonic (typed, never scanned/pasted from an
 * online device ideally), validate its checksum, encrypt and store it.
 */

import { el, toast } from "@satoshivault/ui";
import { encryptVault, validateMnemonic, zeroize } from "@satoshivault/core";
import { AppCtx, View } from "../types";
import { encodeVaultPayload } from "../session";
import { saveVaultBlob, setUsesPassphrase } from "../store";
import { passwordFields } from "./password";

export function importView(app: AppCtx): View {
  const words = el("textarea", {
    rows: "4",
    autocomplete: "off",
    autocapitalize: "none",
    spellcheck: "false",
    placeholder: "12 or 24 words separated by spaces",
  }) as HTMLTextAreaElement;
  const passphraseFlag = el("input", { type: "checkbox" }) as HTMLInputElement;
  const fields = passwordFields();
  const importBtn = el("button", { class: "primary" }, "Validate, Encrypt & Store") as HTMLButtonElement;

  importBtn.addEventListener("click", () => {
    void (async () => {
      const list = words.value.trim().toLowerCase().split(/\s+/).filter((w) => w.length > 0);
      const check = validateMnemonic(list);
      if (!check.ok) {
        toast(check.error ?? "Invalid mnemonic");
        return;
      }
      let password: string;
      try {
        password = fields.read();
      } catch (e) {
        toast(e instanceof Error ? e.message : "Invalid password");
        return;
      }
      importBtn.disabled = true;
      importBtn.textContent = "Encrypting…";
      try {
        await new Promise((r) => setTimeout(r, 30));
        const payload = encodeVaultPayload(list);
        const blob = await encryptVault(payload, password);
        zeroize(payload);
        saveVaultBlob(blob);
        setUsesPassphrase(passphraseFlag.checked);
        words.value = "";
        fields.clear();
        toast("Seed imported — unlock the vault with your password");
        app.show("lock");
      } catch (e) {
        toast(e instanceof Error ? e.message : "Encryption failed");
        importBtn.disabled = false;
        importBtn.textContent = "Validate, Encrypt & Store";
      }
    })();
  });

  const node = el(
    "div",
    {},
    el(
      "div",
      { class: "card" },
      el("h2", {}, "Import Seed"),
      el("div", { class: "banner warn" },
        "Only import on a trusted offline device. Typing a seed on an online computer exposes it."),
      el(
        "div",
        { class: "stack" },
        el("label", { class: "field" }, el("span", { class: "cap" }, "Recovery Words"), words),
        el(
          "label",
          { class: "row" },
          passphraseFlag,
          el("span", { class: "small dim" }, "This seed uses a BIP39 passphrase (asked at every unlock, never stored)"),
        ),
        fields.node,
      ),
    ),
    importBtn,
    el("button", { class: "ghost", onclick: () => app.show("lock") }, "Back"),
  );
  return { node };
}
