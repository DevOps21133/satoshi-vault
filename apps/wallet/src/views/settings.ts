/** Wallet settings: per-network Esplora endpoints, and the privacy story. */

import { clear, el, toast } from "@satoshivault/ui";
import { AppCtx, View } from "../types";
import { DEFAULT_ESPLORA, esploraUrl, networkNames, setEsploraUrl } from "../store";

export function settingsView(_app: AppCtx): View {
  const body = el("div", {});

  const render = () => {
    clear(body);

    const serversCard = el("div", { class: "card" },
      el("h2", {}, "Servers"),
      el("p", { class: "dim small" },
        "Esplora-compatible endpoints (blockstream.info, mempool.space, or your own node's Esplora — " +
        "the private option: a public server learns which addresses you query)."),
    );
    for (const name of networkNames()) {
      const input = el("input", {
        type: "text", autocomplete: "off", spellcheck: "false",
        value: esploraUrl(name),
        placeholder: DEFAULT_ESPLORA[name],
      }) as HTMLInputElement;
      serversCard.append(
        el("label", { class: "field" }, el("span", { class: "cap" }, name), input),
        el("div", { class: "row" },
          el("button", {
            class: "ghost small",
            onclick: () => {
              try {
                setEsploraUrl(name, input.value);
                toast(`${name} endpoint saved`);
                input.value = esploraUrl(name);
              } catch (e) {
                toast(e instanceof Error ? e.message : "Invalid URL");
              }
            },
          }, "Save"),
          el("button", {
            class: "ghost small",
            onclick: () => {
              setEsploraUrl(name, "");
              input.value = esploraUrl(name);
              toast(`${name} endpoint reset`);
            },
          }, "Reset to default"),
        ),
      );
    }

    const aboutCard = el("div", { class: "card" },
      el("h2", {}, "About"),
      el("div", { class: "kv" }, el("span", { class: "k" }, "App"), el("span", { class: "v" }, "Satoshi Vault — Wallet (watch-only)")),
      el("div", { class: "kv" }, el("span", { class: "k" }, "Private keys"), el("span", { class: "v" }, "never — keys live only in the Signer")),
      el("div", { class: "kv" }, el("span", { class: "k" }, "Telemetry"), el("span", { class: "v" }, "none — ever")),
      el("div", { class: "kv" }, el("span", { class: "k" }, "Network use"), el("span", { class: "v" }, "only the Esplora servers configured above")),
      el("p", { class: "dim small" },
        "This app watches balances, builds unsigned transactions, and broadcasts signed ones. " +
        "It cannot spend anything by itself: every signature happens on the air-gapped Signer, over QR codes."),
    );

    body.append(serversCard, aboutCard);
  };

  render();
  return { node: body };
}
