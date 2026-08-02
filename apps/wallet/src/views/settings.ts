/** Wallet settings: per-network Esplora endpoints, and the privacy story. */

import { clear, el, renderQr, toast } from "@satoshivault/ui";
import { AppCtx, View } from "../types";
import { DEFAULT_ESPLORA, esploraUrl, networkNames, setEsploraUrl } from "../store";

/** Project donation address (mainnet P2WPKH, checksum-verified in CI builds). */
export const DONATION_ADDRESS = "bc1quh3humfcqfh7gh3v8d784e29av24y0vl540qcf";

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

    const donateCanvas = el("canvas", {}) as HTMLCanvasElement;
    void renderQr(donateCanvas, `bitcoin:${DONATION_ADDRESS}`, 180);
    const donateCard = el("div", { class: "card center" },
      el("h2", {}, "Support Development ₿"),
      el("p", { class: "dim small" },
        "Satoshi Vault is free and open source. If it protects your bitcoin, " +
        "consider donating a few sats to keep it maintained."),
      el("div", { class: "qr-frame" }, donateCanvas),
      el("div", { class: "addr" }, DONATION_ADDRESS),
      el("button", {
        class: "ghost small",
        onclick: () => {
          void navigator.clipboard.writeText(DONATION_ADDRESS).then(
            () => toast("Donation address copied — thank you!"),
            () => toast("Could not copy — select the address manually"),
          );
        },
      }, "Copy Address"),
    );

    body.append(serversCard, aboutCard, donateCard);
  };

  render();
  return { node: body };
}
