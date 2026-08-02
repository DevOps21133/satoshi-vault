<div align="center">

# ₿

# SATOSHI VAULT

**A security-first, Bitcoin-only, air-gapped wallet system.**

*Cold Signer + Watch-Only Wallet · QR-only signing channel · No telemetry, no cloud, no KYC — ever.*

</div>

---

## Why this exists

**Satoshi Vault exists to protect people worldwide from getting their Bitcoin wallet hacked.** Most wallet thefts trace back to two root causes: seeds generated with weak or predictable randomness, and private keys living on internet-connected devices. Satoshi Vault attacks both — the seed is born in an **entropy ceremony that mixes many independent random sources** (camera noise, microphone noise, pointer motion, device motion, always combined with the OS CSPRNG, each source health-tested per NIST SP 800-90B), and the keys then live only on a **permanently air-gapped device** that is physically incapable of network I/O. Everyone deserves a wallet whose seed no attacker can predict and whose keys no attacker can reach.

Satoshi Vault is two applications that together form an air-gapped Bitcoin wallet:

| App | Runs | Holds | Does |
|-----|------|-------|------|
| **Signer** (`apps/signer`) | on a permanently **offline** device | your seed (encrypted) | generates the seed from multi-source entropy, exports watch-only accounts, reviews & signs PSBTs |
| **Wallet** (`apps/wallet`) | on an online device | **public keys only** | watches balances, builds unsigned transactions, broadcasts signed ones |

The only channel between them is **animated QR codes**, in both directions. The Signer's Content-Security-Policy is `connect-src 'none'` — the page is *incapable* of network I/O even if the device is accidentally online.

## Features

- **BIP39** mnemonics (12–24 words, optional passphrase), generated from a multi-source entropy ceremony: **camera noise, microphone noise, pointer motion, device motion — always mixed with the OS CSPRNG**, with per-source health tests. A failed sensor can never *reduce* security below the OS CSPRNG baseline.
- **BIP32/43/44/49/84/86** hierarchical deterministic derivation.
- All four address families: legacy **P2PKH**, nested SegWit **P2SH-P2WPKH**, native SegWit **P2WPKH**, and Taproot **P2TR** (BIP340/341 key-path).
- **PSBT (BIP174/BIP371)** as the interchange format, with BIP32 derivation metadata in both input and output maps.
- **Verified change detection**: the Signer never trusts fingerprint claims — it re-derives every claimed change path and byte-compares the script. A wallet compromise cannot disguise an attacker output as change.
- **Fee-attack defense**: every input carries the full previous transaction (`non_witness_utxo`), verified against its txid, *in addition to* `witness_utxo` — a lying server or tampered QR cannot misstate input amounts.
- **Coin control** (spend exactly the UTXOs you pick), **RBF** by default, live fee estimates, manual fee rates.
- **Encrypted vault**: Argon2id (64 MiB, t=3) → AES-256-GCM, header authenticated as AAD.
- Electrum-style **Esplora** backends (blockstream.info / mempool.space / your own node), configurable per network.
- **mainnet · testnet · signet · regtest**.
- Address book, watch-only account import via QR, idle auto-lock, memory zeroization of key material.
- **Zero** telemetry, analytics, cloud services, accounts, or tracking of any kind.

## Quick start

Requires Node.js ≥ 20.

```bash
git clone https://github.com/DevOps21133/satoshi-vault
cd satoshi-vault
npm install
npm test                      # 148 tests incl. official BIP vectors

npm run dev -w @satoshivault/signer   # http://localhost:5180  (put THIS device offline)
npm run dev -w @satoshivault/wallet   # http://localhost:5181
```

Production bundles (`npm run build`) are fully static — serve `apps/*/dist` from any static host, or open them from a USB stick on the air-gapped machine.

### Android APKs

Installable APKs live **in this repository** under [`apk/`](apk/) — rebuilt and committed by CI on every push to `main`, and also published to [Releases → `apk-latest`](https://github.com/DevOps21133/satoshi-vault/releases/tag/apk-latest):

- **`satoshi-vault-signer.apk`** — declares **no INTERNET permission**: Android itself denies the app any network socket, enforcing the air gap at the OS level on top of the page's `connect-src 'none'` CSP. Cloud backup and device-to-device transfer of the encrypted vault are disabled.
- **`satoshi-vault-wallet.apk`** — INTERNET + CAMERA only.

These are debug-signed test builds: enable "install unknown apps", verify the `SHA256SUMS.txt`, and uninstall the previous build before installing a newer one.

### Intended deployment

1. Build `apps/signer/dist`, copy it to a device that will **never touch a network again** (old phone/laptop, radios off).
2. Run the Wallet on your daily machine, pointed at **your own node's Esplora** for privacy.
3. Create the vault on the Signer → export the watch-only account QR → scan it in the Wallet.
4. Spend: Wallet builds a PSBT → QR → Signer reviews **on its own trusted screen** and signs → QR → Wallet verifies byte-for-byte and broadcasts.

## Repository layout

```
packages/core   @satoshivault/core — all consensus/crypto logic (BIP39/32, addresses,
                tx/sighash/signing, PSBT, coin selection, entropy, vault crypto,
                QR chunking, Esplora client). Pure TypeScript, no DOM.
packages/ui     @satoshivault/ui — DOM helpers, QR render/scan, the ₿ theme.
apps/signer     the cold vault (CSP: connect-src 'none')
apps/wallet     the watch-only wallet
docs/           architecture, threat model, cryptography, dependency audit
```

## Security model (short version)

- The Signer trusts **nothing** it receives: PSBTs, QR payloads, and stored blobs are hostile input.
- The Wallet trusts **no server**: scripts and amounts are re-derived/re-verified locally; Esplora can censor but cannot forge.
- The QR channel is untrusted **in both directions**: the Wallet verifies the signed transaction byte-for-byte against what was reviewed before broadcasting.
- All primitives come from audited libraries (`@noble/curves`, `@noble/hashes`, `@scure/base`). **No hand-rolled cryptography.**

Read the full documents: [Threat Model](docs/THREAT_MODEL.md) · [Architecture](docs/ARCHITECTURE.md) · [Cryptography](docs/CRYPTOGRAPHY.md) · [Dependencies](docs/DEPENDENCIES.md) · [Audit Checklist](docs/AUDIT_CHECKLIST.md)

## Verify, don't trust

This software is open source under the [MIT license](LICENSE) so you can audit every line. It has **not yet received a third-party security audit** — treat it accordingly: start on testnet/signet, use small amounts first, and keep your seed words on paper regardless of any software.

Satoshi Vault is a from-scratch implementation; **no code was copied from any wallet project**.

## Reporting a vulnerability

See [SECURITY.md](SECURITY.md). Please report privately before disclosure.

## Donate ₿

Satoshi Vault is free, open source, and will never monetize you — no telemetry, no accounts, no paid tiers. If it helps keep your bitcoin safe and you want to support development, donations are gratefully accepted:

```
bc1quh3humfcqfh7gh3v8d784e29av24y0vl540qcf
```

(Bitcoin mainnet, native SegWit P2WPKH. The same address is shown with a QR code in the Wallet app under **Settings → Support Development**.)

---

<div align="center">

*Not your keys, not your coins.* **₿**

</div>
