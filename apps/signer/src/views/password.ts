/** Shared "choose a vault password" fields with confirmation. */

import { el } from "@satoshivault/ui";

export const MIN_PASSWORD_LENGTH = 10;

export interface PasswordFields {
  node: HTMLElement;
  /** Returns the password, or throws with a user-facing message. */
  read(): string;
  clear(): void;
}

export function passwordFields(): PasswordFields {
  const pw = el("input", { type: "password", autocomplete: "new-password", placeholder: `Min ${MIN_PASSWORD_LENGTH} characters` });
  const confirm = el("input", { type: "password", autocomplete: "new-password", placeholder: "Repeat password" });
  const node = el(
    "div",
    { class: "stack" },
    el("label", { class: "field" }, el("span", { class: "cap" }, "Vault Password"), pw),
    el("label", { class: "field" }, el("span", { class: "cap" }, "Confirm Password"), confirm),
  );
  return {
    node,
    read() {
      if (pw.value.length < MIN_PASSWORD_LENGTH) {
        throw new Error(`Password must be at least ${MIN_PASSWORD_LENGTH} characters`);
      }
      if (pw.value !== confirm.value) throw new Error("Passwords do not match");
      return pw.value;
    },
    clear() {
      pw.value = "";
      confirm.value = "";
    },
  };
}
