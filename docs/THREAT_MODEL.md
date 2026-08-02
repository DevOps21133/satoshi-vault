# Threat Model

## Assets

1. **The seed** (BIP39 entropy/words + optional passphrase) — total loss of
   funds if compromised.
2. **The master private key / derived keys** (in Signer memory while
   unlocked).
3. **Transaction integrity** — what the user approves must be what is
   broadcast.
4. **Privacy** — xpub, addresses, balances, transaction graph.
5. **Availability** — ability to spend when needed (lowest priority; Bitcoin
   itself provides recovery via the seed).

## Roles & trust

| Component | Trusted for | NOT trusted for |
|-----------|-------------|-----------------|
| Signer device | key custody, transaction display | — (it is the root of trust) |
| Wallet device | availability, convenience | anything security-critical — assumed compromisable |
| QR channel | nothing | integrity or honesty in either direction |
| Esplora server | availability | integrity of amounts/scripts, privacy |
| This codebase | correctness | — (open source so you can verify) |

## Adversaries considered

- **A1 — Malware on the online (Wallet) device.** Can show fake UI, build
  malicious PSBTs, swap QR codes, and see xpub/addresses.
- **A2 — Malicious or compromised Esplora server.** Can lie about UTXOs,
  amounts, fees, confirmations; can censor broadcasts; logs queried
  addresses.
- **A3 — Thief with the Signer device** (powered off / locked).
- **A4 — Evil-maid with brief physical access** to the Signer.
- **A5 — Shoulder surfer / camera** observing screens during ceremonies.
- **A6 — Supply-chain attacker** targeting dependencies.
- **A7 — Malicious QR payloads** (someone shows the Signer arbitrary codes).

## Defenses by adversary

### A1 — hot-side compromise (the central scenario)

The Signer treats the Wallet as an adversary:

- **Amounts cannot be forged**: input values are taken only from an embedded
  previous transaction that hashes to the input's txid (`non_witness_utxo`),
  cross-checked against `witness_utxo`. A fake fee therefore requires a
  SHA-256d collision.
- **Change cannot be faked**: change claims are re-derived from the Signer's
  own master key and byte-compared (`classifyOutput`); a mismatch is shown as
  a fake-change attack and counted as money leaving.
- **The trusted display is the Signer's**: recipient addresses, amounts, and
  the fee are rendered on the air-gapped screen before signing. User guidance
  in both apps says to verify **there**.
- **A fee-drain needs a second confirmation**: the Signer computes the
  effective sat/vB and the fee as a share of the coins being spent, and a
  transaction that is abnormal on any axis (>100k sat, >300 sat/vB, >10% of
  the input value) is flagged in red and cannot be signed on the first press.
  It is a warning rather than a cap, so a legitimately urgent high fee remains
  possible — with the number stated on the confirm button.
- **The signed result can't be tampered**: the Wallet's `verifySignedTx`
  refuses to broadcast anything that differs from the reviewed PSBT — and
  even if malware bypasses its own check, the signatures only cover the
  transaction the Signer displayed (any mutation invalidates them).
- Residual risk: **address substitution at receive time** — if A1 shows a
  fake receive address, funds go to the attacker. Mitigation: verify receive
  addresses against the Signer (export shows the xpub; a future release will
  add per-address verification on the Signer).

### A2 — malicious server

- Scripts/addresses are derived locally from the xpub — the server cannot
  redirect funds.
- Amounts are verified against raw previous transactions (re-hashed locally).
- Fee estimates are clamped and sanity-checked; the user always sees and can
  override the rate.
- The server **can**: hide UTXOs, delay/censor broadcasts, lie about
  confirmation status (availability/consistency attacks — out of scope), and
  learn your addresses (mitigated by running your own node, the documented
  recommendation).

### A3 — device theft

- The vault blob is sealed with Argon2id (m=64 MiB, t=3, p=1) →
  AES-256-GCM; the header (including KDF parameters) is authenticated as
  AAD, so parameter-downgrade tampering fails authentication.
- A strong password is enforced (≥10 chars) but ultimately the user's
  responsibility; the KDF cost makes GPU guessing expensive.
- The optional **BIP39 passphrase is never persisted** — even the correct
  vault password reveals only the base wallet, not the passphrase wallet
  (plausible deniability / duress layer).
- The shipped Android builds are **not debuggable**, so a thief with a USB
  cable cannot pull the vault blob out of private storage with `adb run-as`,
  and WebView remote debugging (`chrome://inspect`) is unavailable — that
  would otherwise mean arbitrary JS inside an unlocked Signer.

### A4 — evil maid

- Partially out of scope (a modified OS/browser can defeat any web app). The
  static build can be served from read-only media; the ceremony quiz forces
  the words through the user's hands, not just the screen.
- The unlocked window is bounded from three directions: idle auto-lock after
  10 minutes, a 30-second lock once the app is backgrounded (short enough for
  a pocketed phone, long enough to survive an OS permission dialog), and an
  immediate lock on page hide.

### A5 — observation

- Seed words are shown once, behind an explicit reveal, with a warning
  banner; the quiz confirms transcription. QR payloads never contain secrets
  (xpub, PSBT, signed tx only). The vault password is entered in masked
  fields.
- A revealed seed auto-hides after 90 seconds and whenever the view is left,
  so words cannot stay on screen unattended.
- The Signer sets `FLAG_SECURE` on every screen: screenshots, screen
  recorders and `MediaProjection` capture are blocked by Android itself, and
  the recents-list thumbnail is blanked, so seed words cannot leak into a
  screenshot gallery or a screen-sharing session. The Wallet does not set it
  (no secrets, and users legitimately screenshot balances).
- Residual: restoring a seed means typing into a text field, and Android
  keyboards may retain words in a learning dictionary. Documented in the
  README; restore on a device whose keyboard learning is off or cleared.

### A6 — supply chain

- Runtime crypto dependencies are exactly three audited libraries
  (`@noble/curves`, `@noble/hashes`, `@scure/base`) plus `qrcode`/`jsqr` for
  QR I/O in the UI package — see [DEPENDENCIES.md](DEPENDENCIES.md).
- `package-lock.json` pins the tree; CI installs with `npm ci`.
- No framework, no post-install scripts, no native code.
- The Signer's CSP blocks all network egress, so even a malicious dependency
  cannot exfiltrate from the cold side at runtime.
- CI actions are pinned to full commit SHAs (a moved tag would otherwise run
  third-party code in the job that builds the installable binaries), and the
  build job runs with `contents: read` — only a separate publish job, which
  handles nothing but finished artifacts, can write to the repository.
- The build asserts against the **compiled APK**, not the source: the Signer
  must have no `INTERNET` permission and neither app may be debuggable. A
  dependency whose manifest merge reintroduces either one fails the build.

### A7 — malicious QR payloads

- Every payload is parsed as hostile: strict grammar (`SV1:` protocol),
  size caps, integrity hash over the reassembled payload, strict PSBT/
  transaction parsers with bounds checks, and full re-validation of account
  exports (rejecting private-key material in imports).

## Entropy failure

Seed generation mixes **all** sensor sources into a SHA-256 sponge **together
with 32 bytes of OS CSPRNG output**, and health-tests each source
(repetition-count and adaptive-proportion tests, plus a structural screen for
periodic sources — a stuck 8-bit counter or an alternating pattern passes both
800-90B tests while carrying no entropy, so it is rejected outright). A stuck
camera, silent mic, or hostile sensor can add zero entropy but can never
subtract: the output is never weaker than the OS CSPRNG alone.

## Explicit non-goals

- Defending an **unlocked** Signer in an attacker's hands.
- A fully compromised OS/browser on the Signer device.
- Network-level privacy beyond "use your own node" (no built-in Tor).
- Multisig (single-sig only in this release).
- Hardware side channels (timing/EM/power) beyond using constant-time
  library primitives.
