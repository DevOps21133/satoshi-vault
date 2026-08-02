# Dependency Audit

Every runtime dependency must justify its existence. The bar: audited, or
trivially auditable, with no transitive dependency tree and no native code.

## Runtime dependencies

### `@satoshivault/core`

| Package | Version | Why | Audit status |
|---------|---------|-----|--------------|
| `@noble/curves` | ^1.9.2 | secp256k1 ECDSA + BIP340 Schnorr. The de-facto audited pure-JS curve library. | Cure53 & community audits (see repo) |
| `@noble/hashes` | ^1.8.0 | SHA-2, RIPEMD-160, HMAC, PBKDF2, Argon2id. Same author/audit trail. | Cure53 & community audits |
| `@scure/base` | ^1.2.6 | base58check, bech32/bech32m, base64url. Same author/audit trail. | Audited (see repo) |

Zero transitive dependencies. AES-256-GCM deliberately uses **WebCrypto**
(platform-native, constant-time) instead of a JS implementation.

### `@satoshivault/ui`

| Package | Version | Why | Notes |
|---------|---------|-----|-------|
| `qrcode` | ^1.5.4 | QR encoding to canvas. | Handles **public data only** (xpub/PSBT/txn). Deterministic, no network. |
| `jsqr` | ^1.4.0 | QR decoding from camera frames. | Public data only; frames processed in-memory, discarded. |

### Apps (`signer`, `wallet`)

Only the two workspace packages above. **No UI framework** — vanilla DOM.
This is a deliberate TCB decision: no React/Vue supply chain, no virtual-DOM
sanitization pitfalls, `textContent` everywhere.

## Dev-only dependencies

TypeScript, Vite, Vitest, ESLint (+@typescript-eslint), @types/*. These never
ship in a bundle; the built apps are static files. Bundling is done by Vite
(Rollup+esbuild) from the lockfile in CI.

## Supply-chain controls

- `package-lock.json` committed; CI uses `npm ci` (exact-tree install).
- No lifecycle/post-install scripts required by any runtime dependency.
- No native modules anywhere in the runtime path.
- The Signer's CSP (`connect-src 'none'`) means even a fully malicious
  runtime dependency has no way to exfiltrate data from the cold device.
- Renovate/dependabot updates should be reviewed with diffs, not auto-merged
  (crypto libraries especially).

## Update policy

Crypto libraries are pinned by caret to a major version and bumped only after
reviewing the upstream changelog and audit notes. Anything touching key
material gets a manual diff review before merge.
