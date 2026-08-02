/**
 * Vault creation: entropy ceremony → mnemonic display → written-backup quiz →
 * password → encrypted vault on disk. The mnemonic exists in memory only for
 * the duration of this flow.
 */

import { clear, el, toast } from "@satoshivault/ui";
import { encryptVault, entropyToMnemonic, EntropyProgress, zeroize } from "@satoshivault/core";
import { AppCtx, View } from "../types";
import { Ceremony } from "../ceremony";
import { encodeVaultPayload } from "../session";
import { saveVaultBlob, setUsesPassphrase } from "../store";
import { passwordFields } from "./password";

export function createView(app: AppCtx): View {
  const body = el("div", {});
  let ceremony: Ceremony | null = null;
  let hideTimer: ReturnType<typeof setTimeout> | null = null;

  const clearHideTimer = () => {
    if (hideTimer) clearTimeout(hideTimer);
    hideTimer = null;
  };

  const destroy = () => {
    clearHideTimer();
    ceremony?.stop(true);
    ceremony = null;
  };

  // --- step 1: configuration -------------------------------------------------
  const stepConfig = () => {
    const strength = el("select", {}) as HTMLSelectElement;
    strength.append(
      el("option", { value: "256", selected: true }, "24 words (256-bit) — recommended"),
      el("option", { value: "128" }, "12 words (128-bit)"),
    );
    const passphraseFlag = el("input", { type: "checkbox" }) as HTMLInputElement;

    clear(body);
    body.append(
      el(
        "div",
        { class: "card" },
        el("h2", {}, "New Seed"),
        el("p", {}, "Your seed is generated from camera, microphone and motion entropy, " +
          "mixed with the operating system's secure random generator. It never leaves this device."),
        el("hr", { class: "sep" }),
        el(
          "div",
          { class: "stack" },
          el("label", { class: "field" }, el("span", { class: "cap" }, "Seed Strength"), strength),
          el(
            "label",
            { class: "row" },
            passphraseFlag,
            el("span", { class: "small dim" },
              "I will use a BIP39 passphrase (entered at every unlock, never stored — losing it loses the funds)"),
          ),
        ),
      ),
      el("button", {
        class: "primary",
        onclick: () => void stepCeremony(parseInt(strength.value, 10) as 128 | 256, passphraseFlag.checked),
      }, "Begin Entropy Ceremony"),
      el("button", { class: "ghost", onclick: () => app.show("lock") }, "Back"),
    );
  };

  // --- step 2: the ceremony --------------------------------------------------
  const stepCeremony = async (strengthBits: 128 | 256, usePassphrase: boolean) => {
    ceremony = new Ceremony(strengthBits);
    const videoBox = el("div", {});
    const fill = el("div", { class: "fill" });
    const meter = el("div", { class: "meter" }, fill);
    const stats = el("div", { class: "dim small center" }, "0 / 0 bits");
    const micFill = el("div", { class: "fill" });
    const micMeter = el("div", { class: "meter" }, micFill);
    const warnings = el("div", {});
    const generateBtn = el("button", { class: "primary", disabled: true }, "Collecting Entropy…") as HTMLButtonElement;
    const seenErrors = new Set<string>();

    clear(body);
    body.append(
      el(
        "div",
        { class: "card" },
        el("h2", {}, "Entropy Ceremony"),
        el("p", {}, "Point the camera at a moving scene, make some noise, wiggle the pointer, shake the device."),
        videoBox,
        el("div", { class: "stack" },
          el("label", { class: "field" }, el("span", { class: "cap" }, "Entropy Collected"), meter, stats),
          el("label", { class: "field" }, el("span", { class: "cap" }, "Microphone Level"), micMeter),
        ),
        warnings,
      ),
      generateBtn,
      el("button", { class: "ghost", onclick: () => { destroy(); stepConfig(); } }, "Cancel"),
    );

    const onProgress = (p: EntropyProgress) => {
      fill.style.width = `${Math.round(p.ratio * 100)}%`;
      stats.textContent = `${p.creditedBits} / ${p.targetBits} bits` +
        (p.failedSources.length ? ` — unhealthy: ${p.failedSources.join(", ")}` : "");
      if (p.ratio >= 1 && generateBtn.disabled) {
        generateBtn.disabled = false;
        generateBtn.textContent = "Generate Seed";
      }
    };

    generateBtn.addEventListener("click", () => {
      if (!ceremony) return;
      let entropy: Uint8Array;
      try {
        entropy = ceremony.extract(strengthBits === 256 ? 32 : 16);
      } catch (e) {
        toast(e instanceof Error ? e.message : "Entropy target not met");
        return;
      }
      ceremony.stop(false);
      ceremony = null;
      const words = entropyToMnemonic(entropy);
      zeroize(entropy);
      stepBackup(words, usePassphrase);
    });

    await ceremony.start(videoBox, {
      onProgress,
      onMicLevel: (level) => { micFill.style.width = `${Math.round(level * 100)}%`; },
      onSensorError: (sensor, message) => {
        if (seenErrors.has(sensor)) return;
        seenErrors.add(sensor);
        warnings.append(el("div", { class: "banner warn" }, message));
      },
    });
  };

  // --- step 3: show the words ------------------------------------------------
  const HIDE_AFTER_MS = 90_000;
  const stepBackup = (words: string[], usePassphrase: boolean) => {
    // The words auto-hide after a short window: an unattended or
    // shoulder-surfed screen must not display the seed indefinitely.
    const holder = el("div", {});
    const showWords = () => {
      clearHideTimer();
      clear(holder);
      holder.append(el("div", { class: "words" },
        ...words.map((w, i) => el("div", { class: "w" }, el("b", {}, String(i + 1)), w))));
      hideTimer = setTimeout(hideWords, HIDE_AFTER_MS);
    };
    const hideWords = () => {
      clearHideTimer();
      clear(holder);
      holder.append(
        el("div", { class: "banner warn" }, "Words hidden automatically (screen-exposure protection)."),
        el("button", { class: "ghost", onclick: showWords }, "Reveal Again"),
      );
    };
    showWords();

    clear(body);
    body.append(
      el(
        "div",
        { class: "card" },
        el("h2", {}, "Recovery Seed"),
        el("div", { class: "banner bad" },
          "Write these words on paper, in order. Anyone with these words can take your bitcoin. " +
          "Never photograph them, never type them into an online device."),
        holder,
      ),
      el("button", { class: "primary", onclick: () => { clearHideTimer(); stepQuiz(words, usePassphrase); } }, "I Wrote Them Down"),
      el("button", { class: "ghost", onclick: () => { clearHideTimer(); toast("Seed discarded"); app.show("lock"); } }, "Abort"),
    );
  };

  // --- step 4: prove the backup ----------------------------------------------
  const stepQuiz = (words: string[], usePassphrase: boolean) => {
    const indices = randomIndices(3, words.length);
    const inputs = indices.map(() =>
      el("input", { type: "text", autocomplete: "off", autocapitalize: "none", spellcheck: "false" }));

    clear(body);
    body.append(
      el(
        "div",
        { class: "card" },
        el("h2", {}, "Verify Backup"),
        el("p", {}, "Type the requested words from your paper backup."),
        el("div", { class: "stack" },
          ...indices.map((idx, k) =>
            el("label", { class: "field" }, el("span", { class: "cap" }, `Word #${idx + 1}`), inputs[k]!))),
      ),
      el("button", {
        class: "primary",
        onclick: () => {
          const ok = indices.every((idx, k) => inputs[k]!.value.trim().toLowerCase() === words[idx]);
          if (!ok) {
            toast("One or more words are wrong — check your backup");
            return;
          }
          stepPassword(words, usePassphrase);
        },
      }, "Verify"),
      el("button", { class: "ghost", onclick: () => stepBackup(words, usePassphrase) }, "Show Words Again"),
    );
  };

  // --- step 5: encrypt and store ---------------------------------------------
  const stepPassword = (words: string[], usePassphrase: boolean) => {
    const fields = passwordFields();
    const saveBtn = el("button", { class: "primary" }, "Encrypt & Store") as HTMLButtonElement;

    saveBtn.addEventListener("click", () => {
      void (async () => {
        let password: string;
        try {
          password = fields.read();
        } catch (e) {
          toast(e instanceof Error ? e.message : "Invalid password");
          return;
        }
        saveBtn.disabled = true;
        saveBtn.textContent = "Encrypting…";
        try {
          await new Promise((r) => setTimeout(r, 30));
          const payload = encodeVaultPayload(words);
          const blob = await encryptVault(payload, password);
          zeroize(payload);
          saveVaultBlob(blob);
          setUsesPassphrase(usePassphrase);
          fields.clear();
          toast("Vault created — unlock it with your password");
          app.show("lock");
        } catch (e) {
          toast(e instanceof Error ? e.message : "Encryption failed");
          saveBtn.disabled = false;
          saveBtn.textContent = "Encrypt & Store";
        }
      })();
    });

    clear(body);
    body.append(
      el(
        "div",
        { class: "card" },
        el("h2", {}, "Vault Password"),
        el("p", {}, "The seed is encrypted with Argon2id (64 MiB) and AES-256-GCM. " +
          "The password only protects this device's copy — the paper backup is the real recovery."),
        fields.node,
      ),
      saveBtn,
    );
  };

  stepConfig();
  return { node: body, destroy };
}

/** Distinct CSPRNG-chosen indices in [0, max). */
function randomIndices(count: number, max: number): number[] {
  const out = new Set<number>();
  const buf = new Uint32Array(1);
  while (out.size < count) {
    globalThis.crypto.getRandomValues(buf);
    out.add(buf[0]! % max);
  }
  return [...out].sort((a, b) => a - b);
}
