# Architecture

Satoshi Vault is a monorepo of two libraries and two applications. The design
goal is a **minimal trusted computing base**: everything that touches secrets
lives in a small, dependency-light core, and the only bridge between the cold
and hot side is a human-inspectable QR protocol.

```
┌─────────────────────────────┐         ┌─────────────────────────────┐
│  SIGNER (air-gapped)        │         │  WALLET (online)            │
│                             │         │                             │
│  seed ceremony → BIP39      │  XPUB   │  watch-only accounts        │
│  BIP32 master key           │ ──QR──▶ │  gap-limit discovery        │
│  encrypted vault (Argon2id  │         │  coin selection             │
│    + AES-256-GCM)           │  PSBT   │  PSBT construction          │
│  PSBT review + verification │ ◀──QR── │                             │
│  signing (ECDSA + Schnorr)  │         │                             │
│                             │  TXN    │  byte-for-byte verification │
│  CSP: connect-src 'none'    │ ──QR──▶ │  broadcast via Esplora      │
└─────────────────────────────┘         └─────────────────────────────┘
```

## Packages

### `@satoshivault/core` (packages/core)

Pure TypeScript, no DOM dependency, fully unit-tested (official BIP test
vectors). Modules:

| Module | Contents |
|--------|----------|
| `util/bytes`, `util/writer` | byte helpers, hex/varint codecs, `zeroize()`, constant-time compare |
| `crypto/hash` | sha256/sha512/ripemd160/hash160/hmac/pbkdf2 — thin wrappers over `@noble/hashes` |
| `crypto/taproot` | BIP340 x-only keys, BIP341 taproot output-key tweak |
| `bip39/` | mnemonic encode/decode/validate, seed derivation, English wordlist |
| `bip32/hdkey` | HD keys (`HDPrivateKey`/`HDPublicKey`), hardened + normal derivation, fingerprints, xprv/xpub serialization, `wipe()` |
| `address/` | network parameters (mainnet/testnet/signet/regtest), all four script templates, address encode/decode (`base58check`, bech32/bech32m via `@scure/base`) |
| `tx/` | transaction (de)serialization, txid/wtxid, legacy + BIP143 + BIP341 sighashes, ECDSA (low-S) and Schnorr signing, coin selection (branch-and-bound changeless + accumulative fallback), fee/vsize estimation, dust thresholds |
| `psbt/` | BIP174/BIP371 PSBT parse/serialize (hostile-input hardened), input & output map accessors, sign/finalize/extract |
| `entropy/` | the entropy pool (SHA-256 sponge), per-source health tests (repetition + adaptive-proportion, NIST SP 800-90B-inspired), OS CSPRNG mixing |
| `vault/` | Argon2id (via `@noble/hashes`) + AES-256-GCM (WebCrypto) sealed blobs |
| `qr/chunks` | `SV1:` animated-QR chunk protocol (below) |
| `wallet/account` | account xpub export/import (hostile-input parsing), `WatchAccount` public derivation |
| `net/esplora` | Esplora REST client — size caps, timeouts, no redirects/credentials, schema-validated responses |

**Layering rule:** the Signer app imports everything *except* `net/`; the
Wallet app never sees a private-key type in its own code (it only holds
`WatchAccount`).

### `@satoshivault/ui` (packages/ui)

Tiny DOM helpers (`el`, `mount`, `toast`, `brand`, amount formatting), QR
rendering (`qrcode`), camera scanning (`jsqr`), the animated-QR sender, and
the orange/white/black theme. **No `innerHTML` with dynamic data, anywhere.**

## The QR protocol

Every payload crossing the air gap is chunked as:

```
SV1:<TYPE>:<index>/<total>:<groupId>:<base64url-payload>
```

- `TYPE` ∈ `XPUB` (account export), `PSBT` (unsigned/partially-signed), `TXN`
  (fully-signed raw transaction).
- `groupId` = first 8 hex chars of SHA-256(full payload) — frames from
  different payloads can never be mixed, and reassembly is integrity-checked
  against the full hash.
- The receiver (`ChunkAssembler`) accepts frames in any order, tolerates
  repeats, and rejects any frame whose declared total/group conflicts.

Both directions are **untrusted**:

- Signer side: the PSBT is parsed as hostile input; amounts come only from
  verified UTXO data; change claims are re-derived (below).
- Wallet side: `verifySignedTx()` requires the returned transaction to match
  the reviewed PSBT **exactly** — same inputs, same outputs, same order,
  values, scripts, version, locktime — before broadcast.

## The two signature-critical verifications

### 1. Change detection (`classifyOutput`, Signer)

A master fingerprint is *public* information, so a derivation entry claiming
"this output is change" proves nothing by itself. For every output claiming
our fingerprint, the Signer:

1. validates the claimed path shape against the account's BIP43 purpose,
2. re-derives the child key **from its own master key** along that path,
3. rebuilds the expected scriptPubKey for the script type,
4. byte-compares it with the actual output script.

Result: `verified` (true change), `mismatch` (**fake-change attack** — shown
as a red warning and counted as spend), or `foreign` (normal recipient).

### 2. Input-amount verification (fee attack, both sides)

A signer that trusts `witness_utxo` alone can be tricked into paying a huge
fee. The Wallet therefore embeds the **full previous transaction**
(`non_witness_utxo`) for *every* input — after verifying it hashes to the
claimed txid and that its outputs match the server-reported value and the
locally derived script. The Signer re-verifies: prev-tx hash == prevTxid, and
`witness_utxo` (if present) must equal the corresponding output of the
embedded prev tx.

## Apps

Both apps are dependency-free vanilla TypeScript + Vite (no framework — less
supply-chain surface, easier audit). Views are plain functions returning
`{node, destroy()}`; the router always calls `destroy()` (releases camera,
mic, timers) before mounting the next view.

### Signer (`apps/signer`)

- CSP `connect-src 'none'` — network I/O is structurally impossible.
- Online-detection banner if the device is not actually air-gapped.
- Entropy ceremony (camera/mic/pointer/motion + OS CSPRNG) → BIP39 words →
  typed-back quiz → password (min 10 chars) → Argon2id+AES-GCM vault in
  localStorage.
- Idle auto-lock (10 min) wipes the in-memory master key.
- BIP39 passphrase is *never stored* — it is re-entered at every unlock, so a
  stolen vault blob + password still doesn't reveal the passphrase wallet.

### Wallet (`apps/wallet`)

- Holds xpubs only; every stored account is re-validated through the
  hostile-input parser on every load.
- Gap-limit-20 discovery over Esplora, batched.
- Own-node endpoints configurable per network (the privacy option).
- Coin control, RBF, fee presets from live estimates, address book (addresses
  validated before saving).

## Build & reproducibility

- `npm ci && npm run build` produces fully static bundles (`apps/*/dist`).
- Versions are locked by `package-lock.json`; CI builds from the lockfile.
- No post-install scripts, no native modules, no network access at runtime
  beyond the user-configured Esplora endpoint (Wallet only).
