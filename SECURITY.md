# Security Policy

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately via GitHub's *Security → Report a vulnerability* (private
advisory) on this repository. Include:

- affected component (`core`, `signer`, `wallet`, `ui`),
- a reproduction or proof-of-concept,
- your assessment of impact (key extraction, fund loss, privacy leak, DoS).

You will get an acknowledgement as soon as possible. Coordinated disclosure is
appreciated; there is currently no bug-bounty program.

## Scope notes

Particularly interesting classes of findings:

- anything that lets a **hot-side compromise** (malicious Wallet, malicious QR)
  cause the Signer to sign for an unintended output, amount, or fee;
- anything that weakens **seed generation** below the OS CSPRNG baseline;
- **vault-at-rest** attacks better than brute-forcing Argon2id;
- PSBT/transaction **parser memory-safety or logic** issues on hostile input;
- change-detection bypasses (`classifyOutput`), fee-attack bypasses
  (`non_witness_utxo` verification), or signed-tx verification bypasses
  (`verifySignedTx`).

Out of scope: physical attacks on an unlocked device, a fully compromised OS
on the Signer device, and Esplora servers censoring/withholding data
(availability is explicitly not guaranteed by the threat model).

## Supported versions

The `main` branch only. This project has **not yet had a third-party audit**.
