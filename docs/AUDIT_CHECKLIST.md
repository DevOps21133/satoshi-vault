# Third-Party Audit Checklist

A guided map for security auditors. Items are ordered by impact.

## 1. Key generation & custody (Signer)

- [ ] `packages/core/src/entropy/entropy.ts` — pool construction, health
      tests, CSPRNG mixing. Verify: output can never be weaker than the OS
      CSPRNG; health tests can't be gamed into overestimating entropy.
- [ ] `apps/signer/src/ceremony.ts` — sensor capture. Verify: no sensor data
      leaves the device; buffers are zeroized; alpha-channel stripping.
- [ ] `packages/core/src/bip39/mnemonic.ts` — against BIP39 vectors,
      checksum handling, invalid-word behavior.
- [ ] `packages/core/src/bip32/hdkey.ts` — against BIP32 vectors, hardened
      derivation, `wipe()` coverage.
- [ ] `packages/core/src/vault/vault.ts` — Argon2id params, AAD header
      binding, nonce handling, version/downgrade behavior.
- [ ] `apps/signer/src/session.ts` / `store.ts` — what exactly is persisted;
      confirm the BIP39 passphrase never touches storage.

## 2. Transaction integrity (both apps)

- [ ] `packages/core/src/psbt/psbt.ts` — hostile-input parsing: bounds,
      duplicate keys, oversized fields, input/output map key-type confusion
      (in-maps 0x06/0x16 vs out-maps 0x02/0x07).
- [ ] `apps/signer/src/views/sign.ts` — `classifyOutput` (fake-change
      defense): can any claimed path avoid re-derivation? Path validation
      against purpose/network. `psbtFee` amount sourcing.
- [ ] `packages/core/src/tx/sighash.ts` — legacy/BIP143/BIP341 correctness
      against test vectors; amount/script commitments.
- [ ] `apps/wallet/src/build.ts` — non_witness_utxo verification (txid
      re-hash, value/script cross-check), change declaration, coin-flip
      change position.
- [ ] `apps/wallet/src/build.ts#verifySignedTx` — completeness of the
      byte-for-byte check before broadcast.
- [ ] `packages/core/src/tx/coinselect.ts` — fee arithmetic (bigint), dust
      folding, no value creation.

## 3. Untrusted-input surfaces

- [ ] `packages/core/src/qr/chunks.ts` — protocol grammar, size caps, group
      integrity hash, frame-mixing resistance.
- [ ] `packages/core/src/wallet/account.ts` — `accountExportFromJson` and
      `WatchAccount` (must reject xprv material, wrong networks, bad paths).
- [ ] `packages/core/src/net/esplora.ts` — response size caps, timeouts,
      redirect/credential policy, schema validation, bigint parsing.
- [ ] `packages/ui/src/dom.ts` — confirm no `innerHTML`/`insertAdjacentHTML`
      with dynamic data anywhere in the repo.

## 4. Platform hardening

- [ ] `apps/signer/index.html` CSP — `connect-src 'none'`; verify no bypass
      (form-action, prefetch, WebRTC is not used, no service worker).
- [ ] `apps/wallet/index.html` CSP — connect-src scope.
- [ ] Idle auto-lock and `destroy()` lifecycle (camera/mic release).
- [ ] localStorage contents on both apps (nothing secret on the wallet;
      only the sealed blob on the signer).

## 5. Tests & vectors

- [ ] `packages/core/test/` — 138 tests; confirm official BIP39/BIP32/
      BIP143/BIP341/PSBT vectors are actually asserted, not just present.
- [ ] Fuzz the PSBT and transaction parsers (structure-aware fuzzing
      recommended).
- [ ] Reproduce the build: `npm ci && npm run build` from a clean checkout.

## Known-limitations to confirm are documented, not hidden

- JS memory zeroization is best-effort (GC copies).
- Esplora availability/consistency attacks are out of scope.
- Receive-address substitution on a compromised hot device (roadmap:
  Signer-side address verification).
