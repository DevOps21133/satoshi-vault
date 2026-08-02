/** Address book — labels for recipients you pay repeatedly. */

import { clear, el, toast } from "@satoshivault/ui";
import { decodeAddress, NETWORKS, NetworkName } from "@satoshivault/core";
import { AppCtx, View } from "../types";
import { addBookEntry, loadBook, networkNames, removeBookEntry } from "../store";

export function bookView(_app: AppCtx): View {
  const body = el("div", {});

  const render = () => {
    clear(body);
    const entries = loadBook();

    const listCard = el("div", { class: "card" }, el("h2", {}, "Address Book"));
    if (entries.length) {
      for (const e of entries) {
        listCard.append(
          el("div", { class: "row spread", style: "padding:6px 0" },
            el("div", { style: "flex:1; min-width:0" },
              el("div", {}, e.label, " ", el("span", { class: "badge" }, e.network)),
              el("div", { class: "addr small" }, e.address)),
            el("button", {
              class: "ghost small",
              onclick: () => {
                void navigator.clipboard?.writeText(e.address).then(
                  () => toast("Address copied"),
                  () => toast("Copy failed"),
                );
              },
            }, "Copy"),
            el("button", {
              class: "danger small",
              onclick: () => {
                if (!confirm(`Remove "${e.label}" from the address book?`)) return;
                removeBookEntry(e.address, e.network);
                render();
              },
            }, "✕"),
          ),
        );
      }
    } else {
      listCard.append(el("p", { class: "dim" }, "No saved addresses yet."));
    }

    // --- add form ---
    const labelInput = el("input", { type: "text", autocomplete: "off", maxlength: "60", placeholder: "e.g. Exchange withdrawal" }) as HTMLInputElement;
    const addressInput = el("input", { type: "text", autocomplete: "off", spellcheck: "false", placeholder: "bc1…" }) as HTMLInputElement;
    const networkSelect = el("select", {}) as HTMLSelectElement;
    for (const name of networkNames()) networkSelect.append(el("option", { value: name }, name));

    const addCard = el("div", { class: "card" },
      el("h2", {}, "Add Address"),
      el("label", { class: "field" }, el("span", { class: "cap" }, "Label"), labelInput),
      el("label", { class: "field" }, el("span", { class: "cap" }, "Address"), addressInput),
      el("label", { class: "field" }, el("span", { class: "cap" }, "Network"), networkSelect),
      el("button", {
        class: "primary",
        onclick: () => {
          try {
            const networkName = networkSelect.value as NetworkName;
            const address = addressInput.value.trim();
            // Validate before saving — a typo here becomes a typo in a payment.
            decodeAddress(address, NETWORKS[networkName]);
            addBookEntry({ label: labelInput.value.trim(), address, network: networkName });
            toast("Saved");
            render();
          } catch (e) {
            toast(e instanceof Error ? e.message : "Invalid entry");
          }
        },
      }, "Save Address"),
    );

    body.append(listCard, addCard);
  };

  render();
  return { node: body };
}
