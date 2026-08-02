/**
 * Lock screen: welcome (no vault yet) or unlock (vault present).
 * Unlocking runs Argon2id (64 MiB, t=3) — deliberately slow.
 */

import { el, toast } from "@satoshivault/ui";
import { AppCtx, View } from "../types";
import { hasVault, loadVaultBlob, usesPassphrase } from "../store";
import { unlock } from "../session";

export function lockView(app: AppCtx): View {
  if (!hasVault()) return welcome(app);
  return unlockForm(app);
}

function welcome(app: AppCtx): View {
  const node = el(
    "div",
    {},
    el(
      "div",
      { class: "card" },
      el("h2", {}, "Cold Vault Signer"),
      el(
        "p",
        {},
        "This device becomes your Bitcoin vault. It generates your seed from physical entropy, " +
          "stores it encrypted, and signs transactions — all completely offline. " +
          "Keys never touch a network.",
      ),
      el("p", { class: "dim small" },
        "Best practice: install on a dedicated device, then keep it in airplane mode forever."),
    ),
    el(
      "div",
      { class: "stack" },
      el("button", { class: "primary", onclick: () => app.show("create") }, "Create New Vault"),
      el("button", { class: "ghost", onclick: () => app.show("import") }, "Import Existing Seed"),
    ),
  );
  return { node };
}

function unlockForm(app: AppCtx): View {
  const password = el("input", { type: "password", autocomplete: "current-password", placeholder: "Vault password" });
  const passphrase = el("input", { type: "password", autocomplete: "off", placeholder: "BIP39 passphrase" });
  const showPassphrase = usesPassphrase();
  const unlockBtn = el("button", { class: "primary" }, "Unlock Vault") as HTMLButtonElement;

  const submit = async () => {
    const blob = loadVaultBlob();
    if (!blob) {
      toast("Vault is missing");
      return;
    }
    if (password.value.length === 0) {
      toast("Enter your password");
      return;
    }
    unlockBtn.disabled = true;
    unlockBtn.textContent = "Deriving key…";
    try {
      // Yield a frame so the button state paints before Argon2id blocks the thread.
      await new Promise((r) => setTimeout(r, 30));
      const session = await unlock(blob, password.value, passphrase.value);
      password.value = "";
      passphrase.value = "";
      app.setSession(session);
      app.show("home");
    } catch {
      toast("Unable to unlock — wrong password or corrupted vault");
    } finally {
      unlockBtn.disabled = false;
      unlockBtn.textContent = "Unlock Vault";
    }
  };
  unlockBtn.addEventListener("click", () => void submit());
  password.addEventListener("keydown", (e) => {
    if ((e as KeyboardEvent).key === "Enter") void submit();
  });

  const node = el(
    "div",
    {},
    el(
      "div",
      { class: "card" },
      el("h2", {}, "Unlock"),
      el(
        "div",
        { class: "stack" },
        el("label", { class: "field" }, el("span", { class: "cap" }, "Password"), password),
        showPassphrase
          ? el("label", { class: "field" }, el("span", { class: "cap" }, "BIP39 Passphrase"), passphrase)
          : null,
        unlockBtn,
      ),
      el("p", { class: "dim small" }, "Argon2id · 64 MiB · unlocking takes a few seconds by design."),
    ),
  );
  return { node };
}
