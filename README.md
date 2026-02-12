# Sigil

Cryptographic signing and verification for any file. No cloud, no accounts, no dependencies beyond the .NET BCL.

## Install

Requires [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0).

```
dotnet tool install --global Sigil.Sign
```

Update:

```
dotnet tool update --global Sigil.Sign
```

Build from source:

```
git clone <repo-url>
cd <repo-name>
dotnet build Sigil.slnx
dotnet test Sigil.slnx
```

## What it does

Sigil lets you **sign files** and **verify signatures**. That's it.

- Sign a file — Sigil produces a small `.sig.json` file next to it
- Sign a directory — Sigil produces a single `.manifest.sig.json` covering all files atomically
- Sign an archive — Sigil produces an `.archive.sig.json` with per-entry digests for ZIP, tar.gz, and tar files
- Sign a PE binary — Sigil embeds a standard Authenticode signature in the PE and produces a `.sig.json` for trust/policy evaluation
- Anyone can verify the file hasn't been tampered with — the public key is embedded in the envelope
- No key store, no import/export, no hidden state

It works with any file: binaries, SBOMs, container images, config files, tarballs — anything. When signing a CycloneDX or SPDX JSON file, Sigil automatically detects the format and embeds SBOM metadata in the signature envelope.

Sigil also creates **attestations** — signed [in-toto](https://in-toto.io/) statements wrapped in [DSSE](https://github.com/secure-systems-lab/dsse) envelopes that prove how an artifact was built (CI system, inputs, steps). These follow the [SLSA](https://slsa.dev/) provenance standard.

## Why not just use Sigstore/PGP/X.509?

| | Sigil | Sigstore | PGP | X.509 |
|---|---|---|---|---|
| Needs an account | No (keyless/OIDC supported) | Yes (OIDC) | No | Yes (CA) |
| Trusted timestamping | Yes (RFC 3161) | Yes (Rekor) | No | Yes (RFC 3161) |
| Needs internet | No | Yes | No | Depends |
| Stores your email | No | Yes (public log) | Optional | Yes |
| External dependencies | Zero | Many | Many | Many |
| Key management | None (ephemeral), PEM, PFX/PKCS#12, cert store, vault/KMS, or PKCS#11 | Ephemeral | Complex | Complex |
| Vault/KMS support | Yes (4 cloud + PKCS#11) | PKCS#11 | No | Partial |
| Works offline | Yes | No | Yes | Partial |
| Hidden state on disk | None | None | `~/.gnupg/` | Varies |
| SLSA attestations | Yes (DSSE/in-toto) | Yes | No | No |
| Git commit signing | Yes (GPG drop-in) | No | Yes | No |
| Container signing | Yes (OCI 1.1 referrers) | Yes (Cosign) | No | No |
| Batch/manifest signing | Yes (atomic multi-file) | No | No | No |
| Archive signing | Yes (ZIP, tar.gz, tar, NuGet) | No | No | No |
| Authenticode PE signing | Yes (embedded + detached) | No | No | Yes (signtool) |
| Transparency log | Yes (local + remote server + Rekor) | Yes (Rekor) | No | No |
| Post-quantum ready | Yes (ML-DSA-65) | No | No | Partial |

Sigil is for people who want to sign things **without asking permission from a cloud service**.

## Quick start

### Sign a file (ephemeral)

```
sigil sign my-app.tar.gz
```

A key pair is created in memory, the file is signed, and the private key is discarded.

### Verify a file

```
sigil verify my-app.tar.gz
```

The public key is embedded in the `.sig.json` envelope — no key import needed.

### Sign with a persistent key

```
sigil generate -o mykey
sigil sign my-app.tar.gz --key mykey.pem
```

Same fingerprint every time. This enables trust.

### Verify with trust

```
sigil trust create trust.json --name "My Org"
sigil trust add trust.json --fingerprint sha256:a1b2c3...
sigil verify my-app.tar.gz --trust-bundle trust.json
```

## Features

| Feature | Description | Docs |
|---------|-------------|------|
| Ephemeral signing | Zero-setup signing with disposable keys | [Manual](docs/manual.md#quick-start) |
| Multi-algorithm | ECDSA P-256/P-384/P-521, RSA-PSS, ML-DSA-65 (post-quantum) | [Manual](docs/manual.md#choose-your-algorithm) |
| Trust bundles | Declare which keys you trust, with scopes, endorsements, and revocation | [Manual](docs/manual.md#trust-bundles) |
| Attestations | Signed in-toto/DSSE statements for SLSA provenance | [Manual](docs/manual.md#attestations) |
| Policies | Declarative rules for key requirements, timestamps, labels, attestations | [Manual](docs/manual.md#policies) |
| Vault signing | HashiCorp Vault, Azure Key Vault, AWS KMS, Google Cloud KMS | [Manual](docs/manual.md#vault-backed-signing) |
| PKCS#11 | Hardware tokens (YubiKey, HSM) | [Manual](docs/manual.md#pkcs11-hardware-tokens) |
| PFX / Certificate Store | PKCS#12 files and Windows Certificate Store | [Manual](docs/manual.md#pfx-and-certificate-store-signing) |
| Timestamping | RFC 3161 trusted timestamps | [Manual](docs/manual.md#timestamping) |
| Transparency log | Local and remote Merkle tree audit logs (+ Rekor integration) | [Manual](docs/manual.md#transparency-log) |
| Git commit signing | GPG-compatible drop-in replacement | [Manual](docs/manual.md#git-commit-signing) |
| Container signing | OCI 1.1 referrers API for Docker/OCI images | [Manual](docs/manual.md#containeroci-image-signing) |
| Manifest signing | Atomic signing of multiple files in a directory | [Manual](docs/manual.md#batchmanifest-signing) |
| Archive signing | Per-entry verification for ZIP, tar.gz, tar, NuGet packages | [Manual](docs/manual.md#archive-signing) |
| Authenticode PE | Embedded Authenticode + detached Sigil envelope for .exe/.dll | [Manual](docs/manual.md#authenticode-pe-signing) |
| Keyless/OIDC | Ephemeral keys bound to GitHub Actions / GitLab CI identity | [Manual](docs/manual.md#keylessoidc-signing) |
| Discovery | Auto-resolve trust bundles from .well-known, DNS, git repos | [Manual](docs/manual.md#discovery) |
| Trust graph | Build and query relationship graphs across all signing artifacts | [Manual](docs/manual.md#trust-graph-engine) |
| Impact analysis | Instant blast radius assessment when a signing key is compromised | [Manual](docs/manual.md#key-compromise-impact-analysis) |
| Passphrase management | Secure credential chain: CLI, file, env, credential manager, prompt | [Manual](docs/manual.md#passphrase-and-credential-management) |
| SBOM detection | Auto-detect CycloneDX/SPDX and embed metadata in signatures | [Manual](docs/manual.md#sign-an-sbom) |

## How it works

**Identity = Key pair.** Your key fingerprint (SHA-256 of the public key) is your identity. No email, no username, no account.

**Signatures are detached.** Sigil never modifies your files. It produces a separate `.sig.json` envelope containing the file's digests, the public key, and the cryptographic signature.

**Algorithms:**

| Algorithm | Name | Use case |
|-----------|------|----------|
| ECDSA P-256 | `ecdsa-p256` | Default. Fast, compact, widely supported. |
| ECDSA P-384 | `ecdsa-p384` | CNSA suite / government compliance. |
| ECDSA P-521 | `ecdsa-p521` | Maximum NIST curve strength. |
| RSA-PSS | `rsa-pss-sha256` | Legacy interop, 3072-bit keys. |
| ML-DSA-65 | `ml-dsa-65` | Post-quantum (FIPS 204). |
| Ed25519 | `ed25519` | Planned. |

Zero external dependencies — all crypto from .NET's built-in `System.Security.Cryptography`.

## What's coming

- **Time travel verification** — Replay trust decisions as-of a historical date for audits, legal compliance, and incident investigations (`sigil verify artifact.bin --at 2025-03-03`).
- **Environment fingerprint attestation** — Prove a build came from an approved golden image by capturing compiler hash, OS digest, and runner identity as a signed attestation.
- **Anomaly detection** — Behavioral baselines for signing patterns. Detect "validly signed, but not by the usual key for this project" without SaaS.
- **Plugin system** — Extension architecture for CVE scanners, license policy checks, SBOM diffing, and reproducibility validators.
- **Ed25519** — When the .NET SDK ships the native API.

## Documentation

Full reference documentation: **[docs/manual.md](docs/manual.md)**

## License

[AGPL-3.0](LICENSE) — free to use, modify, and distribute. If you distribute a modified version, you must release your source under the same license.
