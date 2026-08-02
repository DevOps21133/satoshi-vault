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

### A4 — evil maid

- Partially out of scope (a modified OS/browser can defeat any web app). The
  static build can be served from read-only media; idle auto-lock (10 min)
  limits the unlocked window; the ceremony quiz forces the words through the
  user's hands, not just the screen.

### A5 — observation

- Seed words are shown once, behind an explicit reveal, with a warning
  banner; the quiz confirms transcription. QR payloads never contain secrets
  (xpub, PSBT, signed tx only). The vault password is entered in masked
  fields.

### A6 — supply chain

- Runtime crypto dependencies are exactly three audited libraries
  (`@noble/curves`, `@noble/hashes`, `@scure/base`) plus `qrcode`/`jsqr` for
  QR I/O in the UI package — see [DEPENDENCIES.md](DEPENDENCIES.md).
- `package-lock.json` pins the tree; CI installs with `npm ci`.
- No framework, no post-install scripts, no native code.
- The Signer's CSP blocks all network egress, so even a malicious dependency
  cannot exfiltrate from the cold side at runtime.

### A7 — malicious QR payloads

- Every payload is parsed as hostile: strict grammar (`SV1:` protocol),
  size caps, integrity hash over the reassembled payload, strict PSBT/
  transaction parsers with bounds checks, and full re-validation of account
  exports (rejecting private-key material in imports).

## Entropy failure

Seed generation mixes **all** sensor sources into a SHA-256 sponge **together
with 32 bytes of OS CSPRNG output**, and health-tests each source
(repetition-count and adaptive-proportion tests). A stuck camera, silent mic,
or hostile sensor can add zero entropy but can never subtract: the output is
never weaker than the OS CSPRNG alone.

## Explicit non-goals

- Defending an **unlocked** Signer in an attacker's hands.
- A fully compromised OS/browser on the Signer device.
- Network-level privacy beyond "use your own node" (no built-in Tor).
- Multisig (single-sig only in this release).
- Hardware side channels (timing/EM/power) beyond using constant-time
  library primitives.
