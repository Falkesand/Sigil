# Sigil

Cryptographic signing and verification for any file. No cloud, no accounts, no dependencies beyond the .NET BCL.

## Table of contents

- [What it does](#what-it-does)
- [Why not just use Sigstore/PGP/X.509?](#why-not-just-use-sigstorepgpx509)
- [Quick start](#quick-start)
  - [Sign a file](#sign-a-file-ephemeral--zero-setup)
  - [Verify a file](#verify-a-file)
  - [Sign with a persistent key](#sign-with-a-persistent-key-for-identity)
  - [Choose your algorithm](#choose-your-algorithm)
  - [Sign an SBOM](#sign-an-sbom)
  - [Sign with a PFX/PKCS#12 file](#sign-with-a-pfxpkcs12-file)
  - [Sign with the Windows Certificate Store](#sign-with-the-windows-certificate-store)
  - [Sign with a vault key](#sign-with-a-vault-key)
  - [Sign with a hardware token](#sign-with-a-hardware-token)
  - [Add a timestamp](#add-a-timestamp)
  - [Create an attestation](#create-an-attestation)
  - [Verify with a policy](#verify-with-a-policy)
  - [Log a signing event](#log-a-signing-event)
  - [Log to a remote server](#log-to-a-remote-server)
  - [Sign git commits](#sign-git-commits)
  - [Sign a container image](#sign-a-container-image)
  - [Verify a container image](#verify-a-container-image)
  - [Sign a directory of files](#sign-a-directory-of-files)
  - [Verify a manifest](#verify-a-manifest)
  - [Sign an archive](#sign-an-archive)
  - [Verify an archive](#verify-an-archive)
  - [Sign a PE binary](#sign-a-pe-binary)
  - [Verify a PE binary](#verify-a-pe-binary)
- [Cross-platform notes](#cross-platform-notes)
- [Ephemeral vs persistent vs vault](#ephemeral-vs-persistent-vs-vault)
- [Envelope format](#envelope-format)
- [Multiple signatures](#multiple-signatures)
- [How it works](#how-it-works)
- [Trust bundles](#trust-bundles)
  - [The problem trust bundles solve](#the-problem-trust-bundles-solve)
  - [Creating a trust bundle](#creating-a-trust-bundle)
  - [Verifying with trust](#verifying-with-trust)
  - [Scopes](#scopes)
  - [Endorsements](#endorsements)
  - [Revoking keys](#revoking-keys)
  - [Viewing a bundle](#viewing-a-bundle)
  - [How trust evaluation works](#how-trust-evaluation-works)
  - [Trust bundle format](#trust-bundle-format)
- [Vault-backed signing](#vault-backed-signing)
  - [HashiCorp Vault](#hashicorp-vault)
  - [Azure Key Vault](#azure-key-vault)
  - [AWS KMS](#aws-kms)
  - [Google Cloud KMS](#google-cloud-kms)
  - [PKCS#11 hardware tokens](#pkcs11-hardware-tokens)
- [Timestamping](#timestamping)
  - [Sign with a timestamp](#sign-with-a-timestamp)
  - [Timestamp an existing signature](#timestamp-an-existing-signature)
  - [Timestamps and expired keys](#timestamps-and-expired-keys)
  - [How timestamping works](#how-timestamping-works)
- [Attestations](#attestations)
  - [The problem attestations solve](#the-problem-attestations-solve)
  - [Create an attestation](#create-an-attestation-1)
  - [Verify an attestation](#verify-an-attestation)
  - [Predicate types](#predicate-types)
  - [Multiple attestation signatures](#multiple-attestation-signatures)
  - [Attestations with trust bundles](#attestations-with-trust-bundles)
  - [How attestations work](#how-attestations-work)
  - [Attestation envelope format](#attestation-envelope-format)
- [Discovery](#discovery)
  - [Well-known URLs](#well-known-urls)
  - [DNS TXT records](#dns-txt-records)
  - [Git repositories](#git-repositories)
  - [Verify with discovery](#verify-with-discovery)
- [Policies](#policies)
  - [The problem policies solve](#the-problem-policies-solve)
  - [Creating a policy](#creating-a-policy)
  - [Verifying with a policy](#verifying-with-a-policy)
  - [Policy rules](#policy-rules)
  - [Policies with attestations](#policies-with-attestations)
  - [Policy format](#policy-format)
- [Transparency log](#transparency-log)
  - [The problem transparency logs solve](#the-problem-transparency-logs-solve)
  - [Append a signing event](#append-a-signing-event)
  - [Verify log integrity](#verify-log-integrity)
  - [Search the log](#search-the-log)
  - [View log entries](#view-log-entries)
  - [Inclusion proofs](#inclusion-proofs)
  - [Consistency proofs](#consistency-proofs)
  - [How the transparency log works](#how-the-transparency-log-works)
  - [Log entry format](#log-entry-format)
- [Remote transparency log](#remote-transparency-log)
  - [The problem remote logs solve](#the-problem-remote-logs-solve)
  - [Sign and log in one step](#sign-and-log-in-one-step)
  - [Enforce logging with policy](#enforce-logging-with-policy)
  - [Running the Sigil LogServer](#running-the-sigil-logserver)
  - [Database providers](#database-providers)
  - [mTLS (mutual TLS)](#mtls-mutual-tls)
  - [Querying the log server](#querying-the-log-server)
  - [Rekor integration](#rekor-integration)
  - [How remote logging works](#how-remote-logging-works)
  - [Transparency receipt format](#transparency-receipt-format)
- [Git commit signing](#git-commit-signing)
  - [Configure git to use Sigil](#configure-git-to-use-sigil)
  - [Sign with a vault key (no private key on disk)](#sign-with-a-vault-key-no-private-key-on-disk)
  - [Sign with an encrypted PEM key](#sign-with-an-encrypted-pem-key)
  - [Sign commits and tags](#sign-commits-and-tags)
  - [Verify commits](#verify-commits)
  - [Wrapper script reference](#wrapper-script-reference)
  - [How git signing works](#how-git-signing-works)
- [Container/OCI image signing](#containeroci-image-signing)
  - [Sign a container image](#sign-a-container-image-1)
  - [Verify a container image](#verify-a-container-image-1)
  - [Registry authentication](#registry-authentication)
  - [How container signing works](#how-container-signing-works)
  - [Signature storage format](#signature-storage-format)
- [Batch/manifest signing](#batchmanifest-signing)
  - [Sign multiple files](#sign-multiple-files)
  - [Verify a manifest](#verify-a-manifest-1)
  - [Filter files with --include](#filter-files-with---include)
  - [Multiple manifest signatures](#multiple-manifest-signatures)
  - [Manifests with trust bundles](#manifests-with-trust-bundles)
  - [How manifest signing works](#how-manifest-signing-works)
  - [Manifest envelope format](#manifest-envelope-format)
- [Archive signing](#archive-signing)
  - [Sign an archive file](#sign-an-archive-file)
  - [Verify an archive](#verify-an-archive-1)
  - [Tampered entry detection](#tampered-entry-detection)
  - [Extra entry detection](#extra-entry-detection)
  - [NuGet package metadata](#nuget-package-metadata)
  - [How archive signing works](#how-archive-signing-works)
  - [Archive envelope format](#archive-envelope-format)
- [Authenticode PE signing](#authenticode-pe-signing)
  - [Sign a PE binary](#sign-a-pe-binary-1)
  - [Verify a PE binary](#verify-a-pe-binary-1)
  - [Tampered PE detection](#tampered-pe-detection)
  - [Dual-signature model](#dual-signature-model)
  - [How Authenticode PE signing works](#how-authenticode-pe-signing-works)
- [Keyless/OIDC signing](#keylessoidc-signing)
  - [Sign in GitHub Actions](#sign-in-github-actions)
  - [Sign in GitLab CI](#sign-in-gitlab-ci)
  - [Sign with a manual OIDC token](#sign-with-a-manual-oidc-token)
  - [Trust OIDC identities](#trust-oidc-identities)
  - [Verify keyless signatures](#verify-keyless-signatures)
  - [How keyless signing works](#how-keyless-signing-works)
- [PFX and certificate store signing](#pfx-and-certificate-store-signing)
  - [Sign with a PFX file](#sign-with-a-pfx-file)
  - [PFX auto-detection](#pfx-auto-detection)
  - [PFX security](#pfx-security)
  - [Windows Certificate Store](#windows-certificate-store)
  - [Certificate store with git signing](#certificate-store-with-git-signing)
  - [LogServer with PFX keys](#logserver-with-pfx-keys)
- [Passphrase and credential management](#passphrase-and-credential-management)
  - [Resolution chain](#resolution-chain)
  - [Passphrase files](#passphrase-files)
  - [Windows Credential Manager](#windows-credential-manager)
  - [Security recommendations](#security-recommendations)
- [Trust graph engine](#trust-graph-engine)
  - [Build a trust graph](#build-a-trust-graph)
  - [Query the trust graph](#query-the-trust-graph)
  - [Revoked key impact analysis](#revoked-key-impact-analysis)
  - [Export for visualization](#export-for-visualization)
  - [How the trust graph works](#how-the-trust-graph-works)
- [CLI reference](#cli-reference)
- [Dotnet tool reference](#dotnet-tool-reference)
- [What's coming](#whats-coming)
- [Install](#install)
- [License](#license)

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

### Sign a file (ephemeral — zero setup)

```
sigil sign my-app.tar.gz
```

That's it. No key generation needed. A key pair is created in memory, the file is signed, and the private key is discarded. This proves the file hasn't been tampered with since signing.

Output:
```
Signed: my-app.tar.gz
Algorithm: ecdsa-p256
Key: sha256:9c8b0e1d9d9c...
Mode: ephemeral (key not persisted)
Signature: my-app.tar.gz.sig.json
```

### Verify a file

```
sigil verify my-app.tar.gz
```

Output:
```
Artifact: my-app.tar.gz
Digests: MATCH
  [VERIFIED] sha256:9c8b0e1d...

All signatures VERIFIED.
```

No key import needed — the public key is embedded in the `.sig.json` envelope.

If someone tampers with the file:

```
FAILED: Artifact digest mismatch — file has been modified.
```

### Sign with a persistent key (for identity)

When you need a stable identity across signatures:

```
sigil generate -o mykey
sigil sign my-app.tar.gz --key mykey.pem
```

Same fingerprint every time. This enables trust — others can verify that you (specifically) signed something.

### Choose your algorithm

```
sigil generate -o mykey --algorithm ecdsa-p384
sigil generate -o mykey --algorithm ecdsa-p521
sigil generate -o mykey --algorithm rsa-pss-sha256
sigil generate -o mykey --algorithm ml-dsa-65
```

When signing with a PEM file, the algorithm is **auto-detected** — no need to specify it:

```
sigil sign my-app.tar.gz --key rsa-key.pem    # auto-detects RSA
sigil sign my-app.tar.gz --key ec-key.pem      # auto-detects P-256, P-384, or P-521
```

For ephemeral signing with a non-default algorithm:

```
sigil sign my-app.tar.gz --algorithm ml-dsa-65
```

### Sign an SBOM

When signing a CycloneDX or SPDX JSON file, Sigil automatically detects the format and embeds metadata:

```
sigil sign sbom.cdx.json --key mykey.pem
```

```
Signed: sbom.cdx.json
Algorithm: ecdsa-p256
Key: sha256:c017446b9040d...
Format: CycloneDX (application/vnd.cyclonedx+json)
Signature: sbom.cdx.json.sig.json
```

Verification shows the SBOM metadata:

```
sigil verify sbom.cdx.json
```

```
Artifact: sbom.cdx.json
Digests: MATCH
SBOM Format: CycloneDX
Spec Version: 1.6
Name: my-app
Version: 3.0.0
Supplier: Acme Corp
Serial Number: urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79
Components: 3
  [VERIFIED] sha256:c017446b9040d...

All signatures VERIFIED.
```

The metadata is embedded in the signed subject, so it is tamper-proof. Non-SBOM files are signed without metadata — no behavior changes for regular files.

### Sign with a PFX/PKCS#12 file

When your signing key is in a PFX or PKCS#12 file (common in Windows/enterprise environments):

```
sigil sign my-app.tar.gz --key signing-cert.pfx --passphrase "my-password"
```

```
Signed: my-app.tar.gz
Algorithm: ecdsa-p256
Key: sha256:a3b4c5d6...
Mode: persistent key
Signature: my-app.tar.gz.sig.json
```

Sigil auto-detects PFX files by their `.pfx` or `.p12` extension — no extra flags needed. The private key is extracted securely, used for signing, and the key material is zeroed from memory. See [PFX and certificate store signing](#pfx-and-certificate-store-signing) for details.

### Sign with the Windows Certificate Store

When your signing key lives in the Windows Certificate Store (Active Directory, Group Policy, CNG/HSM-backed):

```
sigil sign my-app.tar.gz --cert-store abc123def456...
```

```
Signed: my-app.tar.gz
Algorithm: ecdsa-p256
Key: sha256:7f2a3b...
Mode: certificate store
Signature: my-app.tar.gz.sig.json
```

The `--cert-store` option takes the certificate's SHA-1 thumbprint. For non-exportable keys (HSM-backed), signing happens through the certificate's crypto provider — the private key never leaves the hardware. See [PFX and certificate store signing](#pfx-and-certificate-store-signing) for details.

### Sign with a vault key

When your private key lives in a cloud KMS or HashiCorp Vault:

```
sigil sign my-app.tar.gz --vault aws --vault-key alias/my-signing-key
```

```
Signed: my-app.tar.gz
Algorithm: ecdsa-p256
Key: sha256:7f2a3b...
Mode: vault (aws)
Signature: my-app.tar.gz.sig.json
```

The private key never leaves the vault — only the signature is returned. Verification works identically (the public key is embedded in the envelope). See [Vault-backed signing](#vault-backed-signing) for setup details.

### Sign with a hardware token

When your private key lives on an HSM, YubiKey, or smart card:

```
sigil sign my-app.tar.gz --vault pkcs11 --vault-key "pkcs11:token=YubiKey;object=my-key"
```

```
Signed: my-app.tar.gz
Algorithm: ecdsa-p256
Key: sha256:3d4e5f...
Mode: vault (pkcs11)
Signature: my-app.tar.gz.sig.json
```

The private key never leaves the hardware device. See [PKCS#11 hardware tokens](#pkcs11-hardware-tokens) for setup details.

### Add a timestamp

Request an RFC 3161 timestamp from a public TSA when signing:

```
sigil sign release.tar.gz --key mykey.pem --timestamp http://timestamp.digicert.com
```

```
Signed: release.tar.gz
Algorithm: ecdsa-p256
Key: sha256:c017446b...
Timestamp: 2026-02-08T16:48:44Z (verified)
Signature: release.tar.gz.sig.json
```

Or timestamp an existing signature after the fact:

```
sigil timestamp release.tar.gz.sig.json --tsa http://timestamp.digicert.com
```

This provides cryptographic proof of when the signature was created — useful when signing keys have expiry dates. See [Timestamping](#timestamping) for details.

### Create an attestation

Attestations prove **how** an artifact was built — not just that it hasn't been tampered with. They wrap an [in-toto](https://in-toto.io/) statement in a [DSSE](https://github.com/secure-systems-lab/dsse) envelope, signed with the same key infrastructure as regular signatures.

```
sigil attest release.tar.gz --predicate provenance.json --type slsa-provenance-v1
```

```
Attested: release.tar.gz
Algorithm: ecdsa-p256
Key: sha256:9c8b0e1d...
Mode: ephemeral (key not persisted)
Attestation: release.tar.gz.att.json
```

Verify the attestation:

```
sigil verify-attestation release.tar.gz
```

```
Artifact: release.tar.gz
Digests: MATCH
Predicate Type: https://slsa.dev/provenance/v1
Subjects: 1
  [VERIFIED] sha256:9c8b0e1d...

All signatures VERIFIED.
```

See [Attestations](#attestations) for details.

### Verify with a policy

Policies let you enforce organizational rules on top of verification — require multiple signatures, mandatory timestamps, approved algorithms, and more:

```json
{
  "version": "1.0",
  "rules": [
    { "require": "min-signatures", "count": 2 },
    { "require": "timestamp" },
    { "require": "algorithm", "allowed": ["ecdsa-p256", "ecdsa-p384"] }
  ]
}
```

```
sigil verify release.tar.gz --policy policy.json
```

```
Policy Evaluation:
  [PASS] min-signatures: 2 valid signature(s) meet minimum of 2.
  [PASS] timestamp: All valid signatures have verified timestamps.
  [PASS] algorithm: All valid signatures use approved algorithms.

All policy rules PASSED.
```

See [Policies](#policies) for details.

### Log a signing event

Record signing events in an append-only transparency log for auditing:

```
sigil sign release.tar.gz --key mykey.pem
sigil log append release.tar.gz.sig.json
```

```
Appended entry #0 to .sigil.log.jsonl
  Key:      sha256:c017446b...
  Artifact: release.tar.gz
  Digest:   sha256:9c8b0e1d...
```

Verify the log hasn't been tampered with:

```
sigil log verify
```

Search for entries by key or artifact:

```
sigil log search --key sha256:c017446b...
```

See [Transparency log](#transparency-log) for details.

### Log to a remote server

Submit signing events to a shared transparency log server during signing:

```
sigil sign release.tar.gz --key mykey.pem --log-url https://log.example.com --log-api-key secret123
```

```
Signed: release.tar.gz
Logged: https://log.example.com (index 1)
```

The transparency receipt (log index, signed checkpoint, inclusion proof) is embedded in the signature envelope. Verifiers can enforce that signatures were logged:

```
sigil verify release.tar.gz --policy policy.json
```

Where `policy.json` contains `{ "rules": [{ "require": "logged" }] }`.

You can also log to [Sigstore Rekor](https://rekor.sigstore.dev) with the `rekor` shorthand:

```
sigil sign release.tar.gz --key mykey.pem --log-url rekor
```

See [Remote transparency log](#remote-transparency-log) for details.

### Sign git commits

Sigil can replace GPG for git commit and tag signing:

```
sigil generate -o mykey
sigil git config --key mykey.pem --global
git commit -m "Signed with Sigil"
git verify-commit HEAD
```

Or sign with a vault key — no private key on disk:

```
sigil git config --vault hashicorp --vault-key transit/my-signing-key --global
git commit -m "Signed with vault key"
```

See [Git commit signing](#git-commit-signing) for details.

### Sign a container image

Sign an OCI container image directly in the registry — no need to pull it first:

```
sigil sign-image ghcr.io/myorg/myapp:v1.0 --key mykey.pem
```

```
Signed: ghcr.io/myorg/myapp:v1.0
Digest: sha256:a1b2c3d4...
Algorithm: ecdsa-p256
Key: sha256:c017446b...
Mode: persistent key
Signature: sha256:e5f6a7b8...
```

The signature is stored as an OCI artifact in the same registry, discoverable via the OCI 1.1 referrers API. See [Container/OCI image signing](#containeroci-image-signing) for details.

### Verify a container image

```
sigil verify-image ghcr.io/myorg/myapp:v1.0
```

```
Image: ghcr.io/myorg/myapp:v1.0
Digest: sha256:a1b2c3d4...
Signatures: 1

  [VERIFIED] Signature #1
    Key: sha256:c01744...
    Algorithm: ecdsa-p256

All signatures VERIFIED.
```

Trust bundles, policies, and discovery all work with container images — same as file signatures. See [Container/OCI image signing](#containeroci-image-signing) for details.

### Sign a directory of files

Sign all files in a directory with a single manifest signature:

```
sigil sign-manifest ./release/
```

```
Manifest signed: 4 files
Algorithm: ecdsa-p256
Key: sha256:0ee53f5c...
Mode: ephemeral (key not persisted)
Output: release/manifest.sig.json
```

Use `--include` to filter files by pattern:

```
sigil sign-manifest ./release/ --include "*.dll" --key mykey.pem
```

See [Batch/manifest signing](#batchmanifest-signing) for details.

### Verify a manifest

```
sigil verify-manifest release/manifest.sig.json
```

```
Manifest: manifest.sig.json (4 files)
  [OK] README.md
  [OK] src/components/Button.cs
  [OK] src/utils/Format.cs
  [OK] tests/Test.cs

Signatures:
  [VERIFIED] sha256:0ee53f5c...

All signatures VERIFIED.
```

Trust bundles, policies, and discovery all work with manifests — same as file signatures. See [Batch/manifest signing](#batchmanifest-signing) for details.

### Sign an archive

Sign a ZIP, tar.gz, or tar archive with per-entry digest verification:

```
sigil sign-archive release.zip --key mykey.pem
```

```
Archive signed: 12 entries
Algorithm: ecdsa-p256
Key: sha256:c017446b...
Mode: persistent key
Output: release.zip.archive.sig.json
```

All signing modes work — ephemeral, persistent, vault, cert store, and PKCS#11. SBOM entries are auto-detected and NuGet `.nupkg` metadata is extracted automatically.

See [Archive signing](#archive-signing) for details.

### Verify an archive

```
sigil verify-archive release.zip
```

```
Archive: release.zip (12 entries)
  [OK] lib/MyLib.dll
  [OK] lib/MyLib.pdb
  [OK] sbom.cdx.json (CycloneDX 1.5)
  ...

Signatures:
  [VERIFIED] sha256:c017446b...

All signatures VERIFIED.
```

Trust bundles, policies, and discovery all work with archives — same as file and manifest signatures. See [Archive signing](#archive-signing) for details.

### Sign a PE binary

Embed an Authenticode signature directly in a Windows PE binary (.exe, .dll):

```
sigil sign-pe MyApp.exe --key code-signing.pfx --passphrase "secret"
```

```
PE signed: MyApp.exe
Subject: CN=My Company
Thumbprint: A1B2C3D4...
Output: MyApp.exe
Envelope: MyApp.exe.sig.json
```

Authenticode requires an X.509 certificate (PFX/P12 or Windows Certificate Store). PEM keys are not supported for PE signing.

See [Authenticode PE signing](#authenticode-pe-signing) for details.

### Verify a PE binary

```
sigil verify-pe MyApp.exe
```

```
PE file: MyApp.exe

Authenticode:
  [VERIFIED] Authenticode signature is valid
  Subject: CN=My Company
  Issuer: CN=My Company
  Thumbprint: A1B2C3D4...
  Digest: SHA256

Sigil envelope:
  [VERIFIED] sha256:c017446b...

  All envelope signatures VERIFIED.
```

Both the embedded Authenticode signature and the detached Sigil envelope are verified. Trust bundles, policies, and discovery work with PE verification. See [Authenticode PE signing](#authenticode-pe-signing) for details.

## Cross-platform notes

Sigil runs on Linux, macOS, and Windows. All multi-line examples in this README use **bash** syntax. The tables below show how to translate to PowerShell and cmd. Where a command differs significantly, a collapsible **PowerShell / cmd** block is provided below it.

**Line continuation:**

| Shell | Syntax | Example |
|-------|--------|---------|
| bash / zsh | `\` | `sigil trust add trust.json \` |
| PowerShell | `` ` `` | ``sigil trust add trust.json ` `` |
| cmd | `^` | `sigil trust add trust.json ^` |

**Environment variables:**

| Shell | Set | Use |
|-------|-----|-----|
| bash / zsh | `export VAR=value` | `$VAR` |
| PowerShell | `$env:VAR = "value"` | `$env:VAR` |
| cmd | `set VAR=value` | `%VAR%` |

**Path separators:** Forward slashes (`/`) work everywhere, including PowerShell and cmd. All Sigil path output uses forward slashes.

## Ephemeral vs persistent vs vault

| | Ephemeral (default) | Persistent (`--key`) | PFX (`--key *.pfx`) | Cert Store (`--cert-store`) | Vault (`--vault`) |
|---|---|---|---|---|---|
| Setup | None | `sigil generate -o keyname` | Obtain PFX file | Install cert in store | Configure vault + auth |
| Identity proof | No (different key each time) | Yes (stable fingerprint) | Yes (stable fingerprint) | Yes (stable fingerprint) | Yes (stable fingerprint) |
| Integrity proof | Yes | Yes | Yes | Yes | Yes |
| MITM protection | No (attacker can re-sign) | Yes (with trusted fingerprint) | Yes (with trusted fingerprint) | Yes (with trusted fingerprint) | Yes (with trusted fingerprint) |
| Key management | None | User manages PEM file | User manages PFX file | Windows cert store | Vault manages key |
| Private key exposure | In memory (discarded) | On disk (PEM file) | On disk (PFX file) | Never leaves store/HSM | Never leaves vault |
| Platform | Any | Any | Any | Windows only | Any |
| CI/CD | Just works | Mount PEM file | Mount PFX file | Windows runners only | IAM roles / service accounts |
| Trust bundles | Not useful | Yes | Yes | Yes | Yes |

## Envelope format

The `.sig.json` envelope is a self-contained, detached signature:

```json
{
  "version": "1.0",
  "subject": {
    "digests": {
      "sha256": "abc123...",
      "sha512": "def456..."
    },
    "name": "my-app.tar.gz",
    "mediaType": "application/vnd.cyclonedx+json",
    "metadata": {
      "sbom.format": "CycloneDX",
      "sbom.specVersion": "1.6",
      "sbom.name": "my-app",
      "sbom.version": "3.0.0",
      "sbom.supplier": "Acme Corp",
      "sbom.serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
      "sbom.componentCount": "3"
    }
  },
  "signatures": [
    {
      "keyId": "sha256:9c8b0e1d...",
      "algorithm": "ecdsa-p256",
      "publicKey": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...",
      "value": "base64...",
      "timestamp": "2026-02-07T14:30:00Z",
      "label": "ci-pipeline",
      "timestampToken": "base64-DER...",
      "transparencyLogUrl": "https://log.example.com",
      "transparencyLogIndex": 1,
      "transparencySignedCheckpoint": "base64...",
      "transparencyInclusionProof": {
        "leafIndex": 0,
        "treeSize": 1,
        "rootHash": "a1b2c3d4...",
        "hashes": []
      }
    }
  ]
}
```

The `publicKey` field contains the base64-encoded SPKI public key. During verification, Sigil computes the fingerprint of this key and checks it matches `keyId` — preventing public key substitution.

The `mediaType` and `metadata` fields are only present for detected SBOM files. They are `null`/absent for regular files.

The `timestampToken` field is present only when an RFC 3161 timestamp has been applied. It contains the base64-encoded DER of a CMS/PKCS#7 signed timestamp token from a Timestamp Authority. See [Timestamping](#timestamping).

The `transparencyLogUrl`, `transparencyLogIndex`, `transparencySignedCheckpoint`, and `transparencyInclusionProof` fields are present only when the signature was submitted to a remote transparency log. See [Remote transparency log](#remote-transparency-log).

## Multiple signatures

Multiple parties can independently sign the same file. A build system signs it, then an auditor signs it — both signatures live in the same envelope. They can even use different algorithms:

```
sigil sign release.tar.gz --key build-key.pem --label "ci-pipeline"
# Later, someone else with a different key type:
sigil sign release.tar.gz --key audit-rsa-key.pem --label "security-review"
```

Verification shows all signatures:

```
Artifact: release.tar.gz
Digests: MATCH
  [VERIFIED] sha256:a1b2c3... (ci-pipeline)
  [VERIFIED] sha256:d4e5f6... (security-review)

All signatures VERIFIED.
```

## How it works

**Identity = Key pair.** Your key fingerprint (SHA-256 of the public key) is your identity. No email, no username, no account.

**Signatures are detached.** Sigil never modifies your files. It produces a separate `.sig.json` envelope containing the file's digests, the public key, and the cryptographic signature.

**Signing payload.** What actually gets signed is:

```
JCS-canonicalized(subject metadata) + SHA-256(file bytes) + JCS-canonicalized(signed attributes)
```

This binds the signature to the file content, its metadata (name, digests, SBOM metadata if present), and all signature entry fields (algorithm, keyId, timestamp, label) — preventing substitution and replay attacks.

**Crypto.** All crypto comes from .NET's built-in `System.Security.Cryptography` — zero external dependencies.

| Algorithm | Name | Use case |
|-----------|------|----------|
| ECDSA P-256 | `ecdsa-p256` | Default. Fast, compact signatures, widely supported. |
| ECDSA P-384 | `ecdsa-p384` | CNSA suite compliance, enterprise/government requirements. |
| ECDSA P-521 | `ecdsa-p521` | Maximum NIST curve strength, compliance frameworks requiring 521-bit keys. |
| RSA-PSS | `rsa-pss-sha256` | Legacy interop, 3072-bit keys. |
| ML-DSA-65 | `ml-dsa-65` | Post-quantum (FIPS 204). Requires platform support. |
| Ed25519 | `ed25519` | Planned — waiting for .NET SDK to ship the native API. |

PEM and PFX auto-detection means you never need to tell Sigil what algorithm a key uses — it parses the key's OID from the DER encoding and dispatches to the correct implementation. PFX files (`.pfx`/`.p12`) are auto-detected by extension.

**SBOM detection.** When a file is signed, Sigil tries to parse it as JSON and checks for CycloneDX (`bomFormat: "CycloneDX"`) or SPDX (`spdxVersion: "SPDX-..."`) markers. Detection never throws — if the file isn't a recognized SBOM, it's signed as a plain file with no metadata.

## Trust bundles

Verifying a signature tells you the file hasn't been tampered with, but it doesn't tell you if you should trust the key that signed it. Trust bundles solve this.

A trust bundle is a signed JSON file that says: "I trust these specific keys, for these purposes, until these dates." Think of it like a browser's list of trusted certificate authorities — except you create your own, for your own keys, without any third party involved.

### The problem trust bundles solve

Without a trust bundle, `sigil verify` answers one question:

> "Was this file signed by the key in the envelope?"

With a trust bundle, it answers a more useful question:

> "Was this file signed by a key I actually trust?"

### Creating a trust bundle

Start by generating keys — one "authority" key that signs the bundle itself, and one or more "signer" keys that sign your actual files:

```
sigil generate -o authority
sigil generate -o ci-key
```

Create an empty bundle:

```
sigil trust create --name "my-project" -o trust.json
```

Add the CI key as a trusted key:

```
sigil trust add trust.json \
  --fingerprint sha256:abc123... \
  --name "CI Pipeline Key"
```

<details>
<summary>PowerShell / cmd</summary>

```powershell
sigil trust add trust.json `
  --fingerprint sha256:abc123... `
  --name "CI Pipeline Key"
```

```batch
sigil trust add trust.json ^
  --fingerprint sha256:abc123... ^
  --name "CI Pipeline Key"
```

</details>

Sign the bundle with the authority key. This locks the bundle — nobody can add or remove keys without the authority's private key:

```
sigil trust sign trust.json --key authority.pem -o trust-signed.json
```

### Verifying with trust

Now when you verify a file, you can pass the trust bundle and tell Sigil which authority you trust:

```
sigil verify release.tar.gz \
  --trust-bundle trust-signed.json \
  --authority sha256:def456...
```

<details>
<summary>PowerShell / cmd</summary>

```powershell
sigil verify release.tar.gz `
  --trust-bundle trust-signed.json `
  --authority sha256:def456...
```

```batch
sigil verify release.tar.gz ^
  --trust-bundle trust-signed.json ^
  --authority sha256:def456...
```

</details>

If the file was signed by a key that's in the bundle, you'll see:

```
Artifact: release.tar.gz
Digests: MATCH
  [TRUSTED] sha256:abc123... (CI Pipeline Key)
           Key is directly trusted.

All signatures TRUSTED.
```

If the signing key isn't in the bundle:

```
  [UNTRUSTED] sha256:999888...
           Key not found in trust bundle.
```

Without `--trust-bundle`, Sigil behaves exactly as before — pure cryptographic verification, no trust decisions.

### Scopes

You can restrict what a key is trusted to do. Scopes are optional — without them, a key is trusted for everything.

```
sigil trust add trust.json \
  --fingerprint sha256:abc123... \
  --name "CI Key" \
  --scope-names "*.tar.gz" "*.zip" \
  --scope-labels "ci-pipeline" \
  --scope-algorithms "ecdsa-p256" \
  --not-after 2027-01-01T00:00:00Z
```

<details>
<summary>PowerShell / cmd</summary>

```powershell
sigil trust add trust.json `
  --fingerprint sha256:abc123... `
  --name "CI Key" `
  --scope-names "*.tar.gz" "*.zip" `
  --scope-labels "ci-pipeline" `
  --scope-algorithms "ecdsa-p256" `
  --not-after 2027-01-01T00:00:00Z
```

```batch
sigil trust add trust.json ^
  --fingerprint sha256:abc123... ^
  --name "CI Key" ^
  --scope-names "*.tar.gz" "*.zip" ^
  --scope-labels "ci-pipeline" ^
  --scope-algorithms "ecdsa-p256" ^
  --not-after 2027-01-01T00:00:00Z
```

</details>

This says: trust this key only for signing `.tar.gz` and `.zip` files, only when labeled `ci-pipeline`, only with ECDSA P-256, and only until January 2027. If any of those conditions aren't met, you'll see `[SCOPE_MISMATCH]` or `[EXPIRED]` instead of `[TRUSTED]`.

### Endorsements

Sometimes you want to say "I trust Key A, and Key A vouches for Key B." Endorsements let you do this without adding Key B directly to the bundle.

```
sigil trust endorse trust.json \
  --endorser sha256:aaa... \
  --endorsed sha256:bbb... \
  --statement "Authorized build key for CI"
```

<details>
<summary>PowerShell / cmd</summary>

```powershell
sigil trust endorse trust.json `
  --endorser sha256:aaa... `
  --endorsed sha256:bbb... `
  --statement "Authorized build key for CI"
```

```batch
sigil trust endorse trust.json ^
  --endorser sha256:aaa... ^
  --endorsed sha256:bbb... ^
  --statement "Authorized build key for CI"
```

</details>

When Sigil evaluates trust, if it finds a matching endorsement from a key that's directly in the bundle, the endorsed key is treated as trusted:

```
  [TRUSTED] sha256:bbb...
           Endorsed by CI Pipeline Key.
```

Endorsements are **non-transitive**: if Key A endorses Key B, and Key B endorses Key C, Key C is **not** trusted. Only the bundle authority decides which endorsements to include, and only direct bundle keys can be endorsers.

Endorsements can also have scopes and expiry dates, further restricting what the endorsed key is trusted for.

### Revoking keys

If a key is compromised or decommissioned, you can revoke it without re-signing the bundle. Revoked keys are rejected during trust evaluation even if they're still in the bundle's key list.

```
sigil trust revoke trust.json \
  --fingerprint sha256:abc123... \
  --reason "Key compromised"
```

<details>
<summary>PowerShell / cmd</summary>

```powershell
sigil trust revoke trust.json `
  --fingerprint sha256:abc123... `
  --reason "Key compromised"
```

```batch
sigil trust revoke trust.json ^
  --fingerprint sha256:abc123... ^
  --reason "Key compromised"
```

</details>

When Sigil evaluates trust for a revoked key:

```
  [REVOKED] sha256:abc123...
           Key revoked on 2026-02-09T10:00:00Z: Key compromised
```

Revocation is permanent and overrides everything — even a valid RFC 3161 timestamp predating the revocation won't save it. If a key is compromised, all signatures from that key are suspect.

If a revoked key is used as an endorser, all its endorsements become invalid too. The endorsed keys fall back to `[UNTRUSTED]` since they lost their trust chain.

After adding revocations, sign the bundle with `sigil trust sign` to lock in the changes.

### Viewing a bundle

```
sigil trust show trust-signed.json
```

```
Trust Bundle: my-project
Version: 1.0
Created: 2026-02-08T12:00:00Z

Keys (2):
  sha256:abc123... (CI Pipeline Key)
    Expires: 2027-01-01T00:00:00Z
    Names: *.tar.gz, *.zip
  sha256:def456... (Release Manager)

Endorsements (1):
  sha256:abc123... -> sha256:bbb888...
    Statement: Authorized build key for CI

Revocations (1):
  sha256:999888...
    Revoked at: 2026-02-09T10:00:00Z
    Reason: Key compromised

Signature: PRESENT
  Signed by: sha256:def456...
  Algorithm: ecdsa-p256
  Timestamp: 2026-02-08T12:00:00Z
```

### How trust evaluation works

When you pass `--trust-bundle` and `--authority` to `sigil verify`, here's what happens for each signature:

1. **Verify the bundle** — Check that the bundle is signed by the authority you specified. If not, the bundle is rejected entirely.
2. **Check the crypto** — If the cryptographic signature is invalid, the key is `Untrusted` regardless of what the bundle says. Crypto trumps trust.
3. **Check revocation** — If the signing key's fingerprint is in the bundle's revocation list, the key is `Revoked`. This overrides everything, including valid timestamps.
4. **Look up the key** — Search for the signing key's fingerprint in the bundle's key list.
5. **If found** — Check expiry, then check scopes. If everything passes: `Trusted`.
6. **If not found** — Search endorsements where this key is endorsed by a key that *is* in the bundle (and that endorser isn't revoked, isn't expired, and the endorsement isn't expired, and the scopes match). If found: `TrustedViaEndorsement`. Otherwise: `Untrusted`.

### Trust bundle format

```json
{
  "version": "1.0",
  "kind": "trust-bundle",
  "metadata": {
    "name": "my-project",
    "created": "2026-02-08T12:00:00Z"
  },
  "keys": [
    {
      "fingerprint": "sha256:abc123...",
      "displayName": "CI Pipeline Key",
      "scopes": {
        "namePatterns": ["*.tar.gz"],
        "labels": ["ci-pipeline"],
        "algorithms": ["ecdsa-p256"]
      },
      "notAfter": "2027-01-01T00:00:00Z"
    }
  ],
  "endorsements": [
    {
      "endorser": "sha256:aaa...",
      "endorsed": "sha256:bbb...",
      "statement": "Authorized build key",
      "timestamp": "2026-02-08T12:00:00Z"
    }
  ],
  "revocations": [
    {
      "fingerprint": "sha256:999888...",
      "revokedAt": "2026-02-09T10:00:00Z",
      "reason": "Key compromised"
    }
  ],
  "signature": {
    "keyId": "sha256:def456...",
    "algorithm": "ecdsa-p256",
    "publicKey": "base64-SPKI...",
    "value": "base64-signature...",
    "timestamp": "2026-02-08T12:00:00Z"
  }
}
```

The `signature` field covers everything above it. When the bundle is signed, Sigil computes the JCS-canonicalized JSON of everything except `signature`, then signs that with the authority key.

## Timestamping

Sigil signatures include a self-asserted `timestamp` field (ISO 8601), but there's no cryptographic proof of when the signature was created. RFC 3161 Trusted Timestamping solves this by having a Timestamp Authority (TSA) counter-sign your signature bytes, providing third-party proof that the signature existed at a specific time.

### Sign with a timestamp

Add `--timestamp` with a TSA URL when signing:

```
sigil sign release.tar.gz --key mykey.pem --timestamp http://timestamp.digicert.com
```

```
Signed: release.tar.gz
Algorithm: ecdsa-p256
Key: sha256:c017446b...
Timestamp: 2026-02-08T16:48:44Z (verified)
Signature: release.tar.gz.sig.json
```

Verification shows the timestamp:

```
sigil verify release.tar.gz
```

```
Artifact: release.tar.gz
Digests: MATCH
  [VERIFIED] sha256:c017446b...
           Timestamp: 2026-02-08T16:48:44Z (verified)

All signatures VERIFIED.
```

If timestamping fails (network error, TSA unavailable), the signature is saved without a timestamp and a warning is printed to stderr. Timestamping is non-fatal — you still get a valid signature.

### Timestamp an existing signature

You can add a timestamp to a signature after the fact using the standalone `timestamp` command:

```
sigil timestamp release.tar.gz.sig.json --tsa http://timestamp.digicert.com
```

```
[0] Timestamped: 2026-02-08T16:48:44Z (verified)
Updated: release.tar.gz.sig.json
```

To timestamp a specific signature in a multi-signature envelope:

```
sigil timestamp release.tar.gz.sig.json --tsa http://timestamp.digicert.com --index 1
```

By default, `timestamp` applies to all signatures that don't already have a timestamp token. Already-timestamped entries are skipped.

### Timestamps and expired keys

This is the key use case for timestamping. If a signing key has a `notAfter` date in a trust bundle and the key has expired, Sigil would normally return `[EXPIRED]`. But if the signature has a valid RFC 3161 timestamp proving it was created **before** the key expired, Sigil treats it as `[TRUSTED]` instead.

```
sigil verify release.tar.gz --trust-bundle trust.json --authority sha256:def456...
```

```
Artifact: release.tar.gz
Digests: MATCH
  [TRUSTED] sha256:c017446b... (CI Key)
           Key is directly trusted.
           Timestamp: 2026-02-08T16:48:44Z (verified)

All signatures TRUSTED.
```

Without the timestamp, this same verification would show `[EXPIRED]` because the key's `notAfter` date has passed. The timestamp proves the signature predates the expiry, so trust is preserved.

This also applies to endorsements — if an endorser key or the endorsement itself has expired, a valid timestamp before the expiry date overrides the `Expired` decision.

### How timestamping works

1. Sigil computes `SHA-256(signature value bytes)` and sends a timestamp request to the TSA
2. The TSA signs the hash with its own key, binding it to a specific time
3. Sigil stores the TSA's response (a CMS/PKCS#7 signed structure) as `timestampToken` in the envelope
4. During verification, Sigil validates the token: checks the hash algorithm is SHA-256, verifies the hash matches the signature bytes, and validates the CMS signature

The timestamp token is self-contained — anyone can verify it without contacting the TSA again. The TSA's certificate chain is validated against the system trust store.

**Public TSA services** (free, no account needed):

| Provider | URL |
|----------|-----|
| DigiCert | `http://timestamp.digicert.com` |
| Sectigo | `http://timestamp.sectigo.com` |
| GlobalSign | `http://timestamp.globalsign.com/tsa/r6advanced1` |

## Attestations

Signatures prove a file hasn't been tampered with. Attestations go further — they prove **how** and **where** the file was built. An attestation bundles a signed [in-toto Statement](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md) (subject + predicate) inside a [DSSE envelope](https://github.com/secure-systems-lab/dsse) (Dead Simple Signing Envelope), using the same key infrastructure as regular Sigil signatures.

Attestation files use the `.att.json` extension (distinct from `.sig.json` for regular signatures).

### The problem attestations solve

A regular signature answers:

> "Has this file been modified since it was signed?"

An attestation answers:

> "What system built this file, from what inputs, using what process?"

This is critical for supply chain security. A signature tells you a file is intact. An attestation tells you it was built by GitHub Actions from a specific commit on a specific branch — not by someone's laptop.

### Create an attestation

First, create a predicate JSON file describing how the artifact was built:

```json
{
  "builder": { "id": "https://github.com/actions/runner" },
  "buildType": "https://slsa.dev/build/v1",
  "invocation": {
    "configSource": {
      "uri": "git+https://github.com/org/repo@refs/heads/main",
      "digest": { "sha1": "abc123..." }
    }
  }
}
```

Then create the attestation:

```
sigil attest release.tar.gz --predicate provenance.json --type slsa-provenance-v1
```

```
Attested: release.tar.gz
Algorithm: ecdsa-p256
Key: sha256:9c8b0e1d...
Mode: ephemeral (key not persisted)
Attestation: release.tar.gz.att.json
```

Sign with a persistent key:

```
sigil attest release.tar.gz --predicate provenance.json --type slsa-provenance-v1 --key mykey.pem
```

Sign with a vault key:

```
sigil attest release.tar.gz --predicate provenance.json --type slsa-provenance-v1 --vault aws --vault-key alias/ci-key
```

Add an RFC 3161 timestamp:

```
sigil attest release.tar.gz --predicate provenance.json --type slsa-provenance-v1 --key mykey.pem --timestamp http://timestamp.digicert.com
```

### Verify an attestation

```
sigil verify-attestation release.tar.gz
```

```
Artifact: release.tar.gz
Digests: MATCH
Predicate Type: https://slsa.dev/provenance/v1
Subjects: 1
  [VERIFIED] sha256:c017446b...

All signatures VERIFIED.
```

If the artifact has been tampered with:

```
FAILED: Subject digest mismatch — artifact has been modified.
```

Filter by predicate type — reject attestations that don't match the expected type:

```
sigil verify-attestation release.tar.gz --type slsa-provenance-v1
```

If the attestation has a different predicate type:

```
Predicate type mismatch: expected 'https://slsa.dev/provenance/v1', got 'https://cyclonedx.org/bom'.
```

### Predicate types

Sigil supports short names for common predicate types, plus any valid URI:

| Short name | URI |
|-----------|-----|
| `slsa-provenance-v1` | `https://slsa.dev/provenance/v1` |
| `spdx-json` | `https://spdx.dev/Document` |
| `cyclonedx` | `https://cyclonedx.org/bom` |
| Any valid URI | Passed through as-is |

Sigil does not validate predicate content — it guarantees integrity and authenticity. Consumers validate the predicate structure against their own schemas.

### Multiple attestation signatures

Multiple parties can sign the same attestation, just like regular signatures:

```
sigil attest release.tar.gz --predicate provenance.json --type slsa-provenance-v1 --key build-key.pem --output release.att.json
sigil attest release.tar.gz --predicate provenance.json --type slsa-provenance-v1 --key audit-key.pem --output release.att.json
```

The second command appends a signature to the existing `.att.json` rather than overwriting it. Verification shows all signatures:

```
sigil verify-attestation release.tar.gz --attestation release.att.json
```

```
Artifact: release.tar.gz
Digests: MATCH
Predicate Type: https://slsa.dev/provenance/v1
Subjects: 1
  [VERIFIED] sha256:a1b2c3...
  [VERIFIED] sha256:d4e5f6...

All signatures VERIFIED.
```

### Attestations with trust bundles

Attestation verification supports the same trust bundle integration as regular signatures. Use `--trust-bundle` or `--discover` to evaluate whether the attestation signer is trusted:

```
sigil verify-attestation release.tar.gz --trust-bundle trust-signed.json --authority sha256:def456...
```

```
Artifact: release.tar.gz
Digests: MATCH
Predicate Type: https://slsa.dev/provenance/v1
Subjects: 1
  [TRUSTED] sha256:c017446b... (CI Pipeline Key)
           Key is directly trusted.

All signatures TRUSTED.
```

Or with discovery:

```
sigil verify-attestation release.tar.gz --discover example.com
```

### How attestations work

**DSSE (Dead Simple Signing Envelope).** Attestations use DSSE instead of Sigil's custom envelope format. DSSE is the standard envelope for in-toto attestations. The key difference: DSSE uses Pre-Authentication Encoding (PAE) for the signing payload instead of JCS canonicalization.

**PAE (Pre-Authentication Encoding).** What gets signed is:

```
"DSSEv1" + SP + len(type) + SP + type + SP + len(body) + SP + body
```

Where `type` is `"application/vnd.in-toto+json"` and `body` is the JSON-serialized in-toto statement. PAE is deterministic by construction — no canonicalization needed.

**in-toto Statement.** The statement contains:
- `_type`: always `"https://in-toto.io/Statement/v1"`
- `subject`: list of artifact names + digest maps
- `predicateType`: URI identifying the predicate schema
- `predicate`: arbitrary JSON (build provenance, SBOM link, vulnerability report, etc.)

**Self-contained verification.** Like regular signatures, DSSE attestation signatures embed the public key and key fingerprint. No external key import is needed for verification.

**Trust adapter.** Attestation verification results are automatically mapped to the same `VerificationResult` type used by the trust evaluator, so trust bundles, scopes, endorsements, and timestamp-based expiry overrides all work identically.

### Attestation envelope format

The `.att.json` file follows the DSSE specification with Sigil extensions:

```json
{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "base64-encoded-statement...",
  "signatures": [
    {
      "keyid": "sha256:abc123...",
      "sig": "base64...",
      "algorithm": "ecdsa-p256",
      "publicKey": "base64-SPKI...",
      "timestamp": "2026-02-09T12:00:00Z",
      "timestampToken": "base64-DER..."
    }
  ]
}
```

The `payload` decodes to an in-toto statement:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "release.tar.gz",
      "digest": { "sha256": "abc123..." }
    }
  ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "builder": { "id": "https://github.com/actions/runner" },
    "buildType": "https://slsa.dev/build/v1"
  }
}
```

The `algorithm`, `publicKey`, `timestamp`, and `timestampToken` fields are Sigil extensions to the DSSE signature format, providing self-contained verification and timestamping support.

## Discovery

Trust bundles are useful, but you still need to distribute them — copy files, share paths, configure CI. Discovery automates this. Organizations publish trust bundles at standard locations, and Sigil fetches them automatically.

Three discovery methods are supported, all using BCL only (zero external dependencies):

### Well-known URLs

Publish your trust bundle at `https://example.com/.well-known/sigil/trust.json`. Anyone can discover it:

```
sigil discover well-known example.com
```

```
Bundle: my-project
Keys: 3
Signature: SIGNED
```

Save it locally with `-o`:

```
sigil discover well-known example.com -o trust.json
```

### DNS TXT records

Add a TXT record at `_sigil.example.com`:

```
_sigil.example.com. IN TXT "v=sigil1 bundle=https://example.com/.well-known/sigil/trust.json"
```

Then discover via DNS:

```
sigil discover dns example.com
```

Sigil sends a raw UDP DNS query (no external resolver library), parses the TXT record, and fetches the bundle from the URL.

### Git repositories

Store your trust bundle in a git repository at `.sigil/trust.json` or `trust.json` in the repo root:

```
sigil discover git https://github.com/org/trust-bundles.git
```

Use a URL fragment to specify a branch or tag:

```
sigil discover git https://github.com/org/trust-bundles.git#v2
```

Sigil performs a shallow clone (`--depth 1`), reads the bundle, and cleans up the temporary directory.

### Verify with discovery

Instead of manually downloading a trust bundle, you can pass `--discover` directly to `sigil verify`:

```
sigil verify release.tar.gz --discover example.com
```

This is equivalent to downloading the bundle and passing `--trust-bundle`, but without the manual step. The authority fingerprint is auto-extracted from the bundle's signature — if the bundle is signed, you don't need to specify `--authority`.

You can still override the authority if needed:

```
sigil verify release.tar.gz --discover example.com --authority sha256:def456...
```

`--discover` and `--trust-bundle` are mutually exclusive — you pick one or the other. If discovery fails, Sigil reports the error and exits (it doesn't fall back to no-trust mode, since you explicitly asked for trust evaluation).

The `--discover` option supports all three schemes:

| Input | Method |
|-------|--------|
| `example.com` | Well-known URL |
| `https://example.com/trust.json` | Direct HTTPS fetch |
| `dns:example.com` | DNS TXT lookup |
| `git:https://github.com/org/repo.git` | Git clone |

## Policies

Trust bundles answer "is this key trusted?" but can't express richer organizational rules. Policies add declarative verification rules that go beyond trust — requiring multiple signatures, mandatory timestamps, approved algorithms, specific labels, or particular signing keys.

A policy is a JSON file with a list of rules. All rules are evaluated (no short-circuit), so you always see a complete pass/fail report.

### The problem policies solve

Without a policy, `sigil verify` answers:

> "Is the signature cryptographically valid (and optionally trusted)?"

With a policy, it answers:

> "Does this signature meet all of my organization's requirements?"

For example: "At least 2 signatures, all timestamped, all using approved algorithms, and at least one from a trusted key in our CI bundle."

### Creating a policy

Create a JSON file with your verification rules:

```json
{
  "version": "1.0",
  "rules": [
    { "require": "min-signatures", "count": 2 },
    { "require": "timestamp" },
    { "require": "algorithm", "allowed": ["ecdsa-p256", "ecdsa-p384"] },
    { "require": "label", "match": "ci-*" },
    { "require": "trusted", "bundle": "trust.json" }
  ]
}
```

Save this as `policy.json` next to your trust bundle.

### Verifying with a policy

Pass `--policy` to `sigil verify`:

```
sigil verify release.tar.gz --policy policy.json
```

```
Artifact: release.tar.gz
Digests: MATCH
  [VERIFIED] sha256:a1b2c3... (ci-pipeline)
  [VERIFIED] sha256:d4e5f6... (security-review)

Policy Evaluation:
  [PASS] min-signatures: 2 valid signature(s) meet minimum of 2.
  [PASS] timestamp: All valid signatures have verified timestamps.
  [PASS] algorithm: All valid signatures use approved algorithms.
  [PASS] label: Found signature with label matching 'ci-*'.
  [PASS] trusted: At least one signature is trusted by the bundle.

All policy rules PASSED.
```

If any rule fails:

```
Policy Evaluation:
  [PASS] min-signatures: 2 valid signature(s) meet minimum of 2.
  [FAIL] timestamp: One or more valid signatures are missing a verified timestamp.
  [PASS] algorithm: All valid signatures use approved algorithms.

Policy evaluation FAILED.
```

`--policy` is mutually exclusive with `--trust-bundle` and `--discover`. The policy's `trusted` rule handles trust internally — it loads and verifies the bundle itself.

### Policy rules

| Rule | Purpose | Required fields |
|------|---------|-----------------|
| `min-signatures` | Require N valid signatures | `count` (>= 1) |
| `timestamp` | All valid signatures must have a verified RFC 3161 timestamp | — |
| `sbom-metadata` | Signature must include SBOM metadata (CycloneDX or SPDX) | — |
| `algorithm` | All signatures must use an approved algorithm | `allowed` (list) |
| `label` | At least one signature must have a label matching a glob pattern | `match` (glob) |
| `trusted` | At least one signature must be trusted by a trust bundle | `bundle` (relative path) |
| `key` | At least one signature must be from a specific key | `fingerprints` (list) |
| `logged` | At least one signature must have a transparency log receipt | `logPublicKey` (optional, base64 SPKI) |

**min-signatures** — Requires at least N cryptographically valid signatures:

```json
{ "require": "min-signatures", "count": 2 }
```

**timestamp** — All valid signatures must have verified RFC 3161 timestamps:

```json
{ "require": "timestamp" }
```

**sbom-metadata** — The signature must include SBOM metadata (only applies to regular signatures, not attestations):

```json
{ "require": "sbom-metadata" }
```

**algorithm** — All valid signatures must use one of the listed algorithms (case-insensitive):

```json
{ "require": "algorithm", "allowed": ["ecdsa-p256", "ecdsa-p384"] }
```

**label** — At least one valid signature must have a label matching the glob pattern (`*` and `?` wildcards):

```json
{ "require": "label", "match": "ci-*" }
```

**trusted** — Loads a trust bundle (path relative to the policy file) and checks that at least one signature is trusted. Optionally specify the authority fingerprint:

```json
{ "require": "trusted", "bundle": "trust.json" }
{ "require": "trusted", "bundle": "trust.json", "authority": "sha256:def456..." }
```

If `authority` is omitted and the bundle is signed, the authority is auto-extracted from the bundle's signature.

**key** — At least one valid signature must be from one of the listed key fingerprints:

```json
{ "require": "key", "fingerprints": ["sha256:abc123...", "sha256:def456..."] }
```

**logged** — At least one valid signature must have a transparency log receipt (log URL, signed checkpoint, and inclusion proof). Optionally verify the checkpoint signature against the log's public key:

```json
{ "require": "logged" }
{ "require": "logged", "logPublicKey": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE..." }
```

Without `logPublicKey`, the rule performs a structural check only (fields present, inclusion proof valid against the Merkle root). With `logPublicKey`, the signed checkpoint is also cryptographically verified against the log's signing key.

### Policies with attestations

Policies work with attestations too:

```
sigil verify-attestation release.tar.gz --policy policy.json
```

Most rules work identically for attestations. The exception is `sbom-metadata`, which only applies to regular signatures (SBOM metadata lives in the `SignatureEnvelope.Subject.Metadata`, not in DSSE envelopes). If a policy includes `sbom-metadata` and is used with `verify-attestation`, that rule will fail with a clear message.

### Policy format

```json
{
  "version": "1.0",
  "rules": [
    { "require": "min-signatures", "count": 2 },
    { "require": "timestamp" },
    { "require": "sbom-metadata" },
    { "require": "algorithm", "allowed": ["ecdsa-p256", "ecdsa-p384"] },
    { "require": "label", "match": "ci-*" },
    { "require": "trusted", "bundle": "trust.json", "authority": "sha256:def456..." },
    { "require": "key", "fingerprints": ["sha256:abc123..."] },
    { "require": "logged" }
  ]
}
```

Only version `1.0` is supported. Each rule must have a `require` field identifying the rule type. Fields that don't apply to a rule type are ignored. Validation rejects unknown rule types, missing required fields, and empty lists.

## Vault-backed signing

When private keys must never leave a hardware security module or cloud KMS, Sigil delegates signing to the vault. The private key is never exposed to the signing tool — Sigil sends data to the vault or hardware token, receives the signature, and embeds it in the envelope. Authentication uses environment variables — no hardcoded secrets. All vault API calls have a 30-second timeout.

### Supported providers

| Provider | `--vault` value | Key reference format | Auth mechanism |
|----------|----------------|----------------------|----------------|
| HashiCorp Vault | `hashicorp` | `transit/<keyname>` or `kv/<path>` | `VAULT_TOKEN` or AppRole |
| Azure Key Vault | `azure` | Key name or full key URL | `DefaultAzureCredential` |
| AWS KMS | `aws` | ARN, key ID, or `alias/<name>` | AWS credential chain |
| Google Cloud KMS | `gcp` | Full resource name | Application Default Credentials |
| PKCS#11 (HSM/YubiKey) | `pkcs11` | RFC 7512 URI or key label | PIN via env var or URI |

### HashiCorp Vault

HashiCorp Vault supports two backends: **Transit** (sign-in-vault) and **KV** (retrieve PEM key).

**Key reference formats:**

```
transit/my-signing-key     # Transit engine (recommended)
my-signing-key             # Transit engine (shorthand)
kv/sigil/my-key            # KV v2 engine (expects "pem" field)
```

**Environment variables:**

| Variable | Required | Description |
|----------|----------|-------------|
| `VAULT_ADDR` | Yes | Vault server URL (HTTPS required except localhost) |
| `VAULT_TOKEN` | One of | Direct token authentication |
| `VAULT_ROLE_ID` | One of | AppRole authentication (with `VAULT_SECRET_ID`) |
| `VAULT_SECRET_ID` | One of | AppRole authentication (with `VAULT_ROLE_ID`) |
| `VAULT_NAMESPACE` | No | Vault namespace |
| `VAULT_MOUNT_PATH` | No | Transit mount path (default: `transit`) |

If neither `VAULT_TOKEN` nor AppRole credentials are set, Sigil falls back to `~/.vault-token`.

**Example:**

```bash
# Linux / macOS
export VAULT_ADDR=https://vault.example.com
export VAULT_TOKEN=hvs.CAES...

# Windows (PowerShell)
$env:VAULT_ADDR = "https://vault.example.com"
$env:VAULT_TOKEN = "hvs.CAES..."

# Windows (cmd)
set VAULT_ADDR=https://vault.example.com
set VAULT_TOKEN=hvs.CAES...
```

```
sigil sign release.tar.gz --vault hashicorp --vault-key transit/my-signing-key
sigil trust sign trust.json --vault hashicorp --vault-key transit/my-signing-key -o trust-signed.json
```

### Azure Key Vault

**Key reference formats:**

```
my-key                                                    # Key name (uses AZURE_KEY_VAULT_URL)
https://myvault.vault.azure.net/keys/my-key               # Full URL (latest version)
https://myvault.vault.azure.net/keys/my-key/abc123...      # Full URL (specific version)
```

**Environment variables:**

| Variable | Required | Description |
|----------|----------|-------------|
| `AZURE_KEY_VAULT_URL` | Yes | Vault URL (e.g., `https://myvault.vault.azure.net`) |

Authentication uses `DefaultAzureCredential`, which tries (in order): environment variables (`AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`), managed identity, workload identity, Azure CLI.

**Example:**

```bash
# Linux / macOS
export AZURE_KEY_VAULT_URL=https://myvault.vault.azure.net

# Windows (PowerShell)
$env:AZURE_KEY_VAULT_URL = "https://myvault.vault.azure.net"

# Windows (cmd)
set AZURE_KEY_VAULT_URL=https://myvault.vault.azure.net
```

```
sigil sign release.tar.gz --vault azure --vault-key my-key
```

### AWS KMS

**Key reference formats:**

```
alias/my-signing-key                                       # Key alias
arn:aws:kms:us-east-1:123456789:key/abcd-1234-efgh         # Full ARN
abcd-1234-efgh-5678                                        # Key ID
```

**Environment variables:**

| Variable | Required | Description |
|----------|----------|-------------|
| `AWS_REGION` | Yes | AWS region (e.g., `us-east-1`) |

Authentication uses the standard AWS credential chain: environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`), EC2/ECS instance roles, web identity (IRSA), `~/.aws/credentials`.

**Example:**

```bash
# Linux / macOS
export AWS_REGION=us-east-1

# Windows (PowerShell)
$env:AWS_REGION = "us-east-1"

# Windows (cmd)
set AWS_REGION=us-east-1
```

```
sigil sign release.tar.gz --vault aws --vault-key alias/my-signing-key
```

### Google Cloud KMS

**Key reference format:**

```
projects/my-project/locations/us/keyRings/my-ring/cryptoKeys/my-key/cryptoKeyVersions/1
```

Authentication uses Application Default Credentials: `GOOGLE_APPLICATION_CREDENTIALS` (service account JSON), `gcloud auth application-default login`, Compute Engine / Cloud Run service account.

**Supported algorithms:** ECDSA P-256, ECDSA P-384, RSA-PSS-SHA256. ECDSA P-521 is not supported by Google Cloud KMS.

**Example:**

```
sigil sign release.tar.gz --vault gcp \
  --vault-key projects/my-project/locations/us/keyRings/my-ring/cryptoKeys/my-key/cryptoKeyVersions/1
```

<details>
<summary>PowerShell / cmd</summary>

```powershell
sigil sign release.tar.gz --vault gcp `
  --vault-key projects/my-project/locations/us/keyRings/my-ring/cryptoKeys/my-key/cryptoKeyVersions/1
```

```batch
sigil sign release.tar.gz --vault gcp ^
  --vault-key projects/my-project/locations/us/keyRings/my-ring/cryptoKeys/my-key/cryptoKeyVersions/1
```

</details>

### PKCS#11 hardware tokens

PKCS#11 is the standard interface for hardware security modules (HSMs), YubiKeys, smart cards, and other cryptographic tokens. The private key never leaves the device — Sigil sends data to the token for signing and receives the signature back.

**Key reference formats:**

```
pkcs11:token=YubiKey;object=my-key                              # RFC 7512 URI (recommended)
pkcs11:token=MyHSM;object=signing-key?module-path=/usr/lib/p11.so  # with explicit library path
pkcs11:token=MyHSM;object=key1?pin-value=1234                   # with PIN in URI (not recommended)
/usr/lib/softhsm/libsofthsm2.so;token=MyToken;object=my-key    # legacy path format
my-key                                                           # plain key label (searches all tokens)
```

**Environment variables:**

| Variable | Required | Description |
|----------|----------|-------------|
| `PKCS11_LIBRARY` | Yes (unless in URI) | Path to the PKCS#11 shared library (`.so`/`.dll`/`.dylib`) |
| `PKCS11_PIN` | No | Token PIN (if not in URI or `--passphrase`) |

**PIN resolution order:** The PIN is resolved from the first available source:

1. `pin-value` in the PKCS#11 URI
2. `--passphrase` CLI option
3. `PKCS11_PIN` environment variable
4. No PIN (some tokens don't require one for signing)

**Library path resolution:** The PKCS#11 library path is resolved from:

1. `module-path` in the URI query string
2. Library path in the legacy path format
3. `PKCS11_LIBRARY` environment variable

**Common PKCS#11 libraries:**

| Device / Software | Library path |
|-------------------|-------------|
| SoftHSM2 (Linux) | `/usr/lib/softhsm/libsofthsm2.so` |
| SoftHSM2 (Windows) | `C:\SoftHSM2\lib\softhsm2.dll` |
| YubiKey (macOS) | `/usr/local/lib/libykcs11.dylib` |
| YubiKey (Linux) | `/usr/lib/libykcs11.so` |
| YubiKey (Windows) | `C:\Program Files\Yubico\Yubico PIV Tool\bin\libykcs11.dll` |
| OpenSC (Linux/macOS) | `/usr/lib/opensc-pkcs11.so` |
| OpenSC (Windows) | `C:\Program Files\OpenSC Project\OpenSC\minidriver\opensc-pkcs11.dll` |
| Thales Luna HSM | `/usr/safenet/lunaclient/lib/libCryptoki2_64.so` |
| AWS CloudHSM | `/opt/cloudhsm/lib/libcloudhsm_pkcs11.so` |

**Example:**

```bash
# Linux / macOS
export PKCS11_LIBRARY=/usr/lib/softhsm/libsofthsm2.so
export PKCS11_PIN=1234

# Windows (PowerShell)
$env:PKCS11_LIBRARY = "C:\SoftHSM2\lib\softhsm2.dll"
$env:PKCS11_PIN = "1234"

# Windows (cmd)
set PKCS11_LIBRARY=C:\SoftHSM2\lib\softhsm2.dll
set PKCS11_PIN=1234
```

```
sigil sign release.tar.gz --vault pkcs11 --vault-key "pkcs11:token=MyToken;object=my-key"
sigil sign release.tar.gz --vault pkcs11 --vault-key my-key
sigil trust sign trust.json --vault pkcs11 --vault-key "pkcs11:token=YubiKey;object=authority" -o trust-signed.json
```

**Supported algorithms:** The algorithm is auto-detected from the token's key type:

| Token key type | Sigil algorithm |
|---------------|-----------------|
| EC P-256 | `ecdsa-p256` |
| EC P-384 | `ecdsa-p384` |
| EC P-521 | `ecdsa-p521` |
| RSA | `rsa-pss-sha256` |

**Security notes:**

- Avoid putting PINs in URIs for production use — prefer `PKCS11_PIN` or `--passphrase`
- PINs in URIs may appear in shell history, process listings, and log files
- The `--passphrase` option is reused for PKCS#11 PINs when using `--vault pkcs11`

**Touch-to-sign devices:** Some hardware tokens (YubiKeys, smart cards) require
physical interaction before signing. Sigil prints "Waiting for PKCS#11 device
(touch may be required)..." to stderr when this might apply. If your terminal
appears to pause during signing, touch or press the button on your device.

## Transparency log

Signing events are ephemeral — once a file is signed, there's no auditable record that the event occurred. A transparency log adds an append-only, Merkle-tree-backed record of signing events that can be verified for integrity. This enables detection of compromised keys (did this key sign something unexpected?) and audit trails (what was signed, when, by whom?).

The log is **local-first** — a JSONL file on disk, no server, no network calls. Integrity is guaranteed by an RFC 6962 Merkle tree with domain-separated hashing.

### The problem transparency logs solve

Without a transparency log, signing is fire-and-forget:

> "Was this file signed?" — Yes, here's the `.sig.json`.

With a transparency log, you can answer richer questions:

> "What has this key signed? When was this artifact last signed? Has anyone tampered with the signing history?"

### Append a signing event

After signing a file, append the signing event to a log:

```
sigil sign release.tar.gz --key mykey.pem
sigil log append release.tar.gz.sig.json
```

```
Appended entry #0 to .sigil.log.jsonl
  Key:      sha256:c017446b...
  Artifact: release.tar.gz
  Digest:   sha256:9c8b0e1d...
```

Each append creates a log entry and updates the Merkle tree checkpoint. Duplicate signatures are rejected — the same signature cannot be logged twice.

For multi-signature envelopes, specify which signature to log:

```
sigil log append release.tar.gz.sig.json --signature-index 1
```

### Verify log integrity

Check that no entries have been tampered with and the Merkle root matches the checkpoint:

```
sigil log verify
```

```
Log integrity verified.
  Entries:     42
  Root hash:   a1b2c3d4...
  Checkpoint:  MATCH
```

If someone modifies a log entry:

```
INTEGRITY VIOLATION detected.
  Invalid entries: [3, 17]
  Checkpoint:      MISMATCH
```

### Search the log

Find entries by key fingerprint, artifact name, or digest:

```
sigil log search --key sha256:c017446b...
```

```
Found 3 entries:
  [0] release-v1.tar.gz  2026-02-09T10:00:00Z  ecdsa-p256
  [5] release-v2.tar.gz  2026-02-09T14:30:00Z  ecdsa-p256
  [8] hotfix.tar.gz      2026-02-09T16:00:00Z  ecdsa-p256
```

```
sigil log search --artifact release.tar.gz
sigil log search --digest sha256:9c8b0e1d...
```

At least one search filter is required.

### View log entries

Display all entries in the log:

```
sigil log show
```

```
Showing 3 entries:
  [0] release.tar.gz     sha256:c017446b...  2026-02-09T10:00:00Z  ecdsa-p256
  [1] my-app.dll         sha256:a1b2c3d4...  2026-02-09T11:00:00Z  ecdsa-p384
  [2] config.json        sha256:d4e5f6a7...  2026-02-09T12:00:00Z  ecdsa-p256
```

Paginate with `--limit` and `--offset`:

```
sigil log show --limit 10 --offset 20
```

### Inclusion proofs

Prove that a specific entry exists in the log without downloading the entire log:

```
sigil log proof --index 1
```

```
Inclusion proof:
  Leaf index: 1
  Tree size:  42
  Root hash:  a1b2c3d4...
  Hashes:     6
Inclusion proof VERIFIED.
```

### Consistency proofs

Prove that the log has only been appended to (never modified or truncated) by comparing an earlier tree state to the current one:

```
sigil log proof --old-size 10
```

```
Consistency proof:
  Old size:  10
  New size:  42
  Old root:  e5f6a7b8...
  New root:  a1b2c3d4...
  Hashes:    4
Consistency proof VERIFIED.
```

### How the transparency log works

**Append-only.** Entries are only appended, never modified or deleted. Each entry records a signing event: who signed (key fingerprint), what was signed (artifact name and digest), when (timestamp), and with what algorithm.

**Merkle tree (RFC 6962).** The log maintains a binary hash tree over all entries. Each leaf is `SHA-256(0x00 || JCS(entry))` (domain-separated from internal nodes). Internal nodes are `SHA-256(0x01 || left || right)`. This enables:

- **Tamper detection** — Modifying any entry changes its leaf hash, which propagates up to a different root hash. The checkpoint stores the expected root.
- **Inclusion proofs** — O(log n) proof that a specific entry is in the log, without revealing other entries.
- **Consistency proofs** — O(log n) proof that a newer log is a strict append of an older log, without comparing all entries.

**JCS canonicalization.** Leaf hashes are computed over the JCS-canonicalized (RFC 8785) JSON of the entry, excluding the `leafHash` field itself. This ensures deterministic, reproducible hashes regardless of JSON serialization order.

**Atomic checkpoint.** After each append, the Merkle root and tree size are written to a checkpoint file using write-to-temp-then-rename for crash safety.

**Duplicate detection.** The SHA-256 of the signature bytes is stored in each entry. Attempting to log the same signature twice returns an error.

### Log entry format

Each line in the `.sigil.log.jsonl` file is a JSON object:

```json
{
  "index": 0,
  "timestamp": "2026-02-09T10:00:00.0000000Z",
  "keyId": "sha256:c017446b...",
  "algorithm": "ecdsa-p256",
  "artifactName": "release.tar.gz",
  "artifactDigest": "sha256:9c8b0e1d...",
  "signatureDigest": "sha256:a1b2c3d4...",
  "label": "ci-pipeline",
  "leafHash": "e5f6a7b8..."
}
```

The `label` field is omitted when null. The `leafHash` is computed from all other fields via JCS canonicalization and domain-separated Merkle leaf hashing.

The checkpoint file (`.sigil.checkpoint`) stores the current tree state:

```json
{
  "treeSize": 42,
  "rootHash": "a1b2c3d4...",
  "timestamp": "2026-02-09T16:00:00.0000000Z"
}
```

## Remote transparency log

A local transparency log only audits what the local signer records. For transparency to have teeth, **verifiers must refuse signatures that weren't logged**, and the log must be shared. Sigil provides two options: a self-hosted **Sigil LogServer** and integration with **Sigstore Rekor**.

### The problem remote logs solve

A local log answers: "What did *I* sign?" A remote log answers: "What did *anyone* sign, and can the log operator prove they haven't tampered with it?"

Remote logs add:

- **Third-party auditability** — anyone can verify the log's integrity, not just the signer
- **Signed checkpoints** — the log server signs the Merkle root, creating a cryptographic commitment
- **Inclusion proofs** — verifiers can confirm a signature entry exists in the log without trusting the server
- **Policy enforcement** — verifiers can reject signatures that weren't logged

### Sign and log in one step

Add `--log-url` to any sign command to submit the signature to a remote log after signing:

```
sigil sign release.tar.gz --key mykey.pem --log-url https://log.example.com --log-api-key secret123
```

```
Signed: release.tar.gz
Logged: https://log.example.com (index 1)
```

The transparency receipt is embedded in the signature envelope:

```json
{
  "transparencyLogUrl": "https://log.example.com",
  "transparencyLogIndex": 1,
  "transparencySignedCheckpoint": "base64...",
  "transparencyInclusionProof": {
    "leafIndex": 0,
    "treeSize": 1,
    "rootHash": "a1b2c3d4...",
    "hashes": []
  }
}
```

Log submission is best-effort — if the log server is unreachable, signing still succeeds with a warning. This matches the behavior of `--timestamp`.

The `--log-url` and `--log-api-key` options are available on `sign`, `sign-manifest`, and `sign-image`.

### Enforce logging with policy

Require that all verified signatures have a transparency log receipt:

```json
{
  "rules": [
    { "require": "logged" }
  ]
}
```

```
sigil verify release.tar.gz --policy policy.json
```

For stronger assurance, verify the log's signed checkpoint cryptographically:

```json
{
  "rules": [
    { "require": "logged", "logPublicKey": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE..." }
  ]
}
```

The `logPublicKey` is the log server's ECDSA signing key in base64-encoded SPKI format. Retrieve it from a running server at `GET /api/v1/log/publicKey`.

### Running the Sigil LogServer

The Sigil LogServer is a standalone ASP.NET Core application. It is **not** embedded in the `sigil` CLI tool.

**Start with a dev certificate (development/testing):**

```
dotnet run --project src/Sigil.LogServer -- \
  --dev-cert \
  --db sigil-log.db \
  --key server-signing.pem \
  --api-key your-secret-key
```

**Start with a production TLS certificate:**

```
dotnet run --project src/Sigil.LogServer -- \
  --cert server.crt \
  --cert-key server.key \
  --db sigil-log.db \
  --key server-signing.pem \
  --api-key your-secret-key
```

**Start with a PFX/PKCS#12 file for both TLS and signing:**

```
dotnet run --project src/Sigil.LogServer -- \
  --cert-pfx server.pfx \
  --cert-password "tls-pass" \
  --db sigil-log.db \
  --key-pfx signing.pfx \
  --key-password "signing-pass" \
  --api-key your-secret-key
```

| Option | Required | Description |
|--------|----------|-------------|
| `--cert` | Yes* | TLS certificate PEM file |
| `--cert-key` | Yes* | TLS private key PEM file |
| `--cert-pfx` | Yes* | TLS PFX/PKCS#12 file (alternative to `--cert`/`--cert-key`) |
| `--cert-password` | No | Password for `--cert-pfx` |
| `--dev-cert` | Yes* | Use ASP.NET Core dev certificate instead of `--cert`/`--cert-key` |
| `--db` | No | SQLite database path (default: `sigil-log.db`) |
| `--key` | Yes** | Server signing key PEM (ECDSA, signs checkpoints) |
| `--key-pfx` | Yes** | Server signing key PFX (alternative to `--key`) |
| `--key-password` | No | Password for `--key-pfx` |
| `--api-key` | Yes | API key for write operations (POST endpoints) |
| `--db-provider` | No | Database provider: `sqlite` (default), `sqlserver`, `postgres` |
| `--connection-string` | No | Connection string for SQL Server or PostgreSQL |
| `--mtls-ca` | No | CA certificate PEM for mutual TLS client verification |
| `--port` | No | HTTPS port (default: 5199) |

*One of `--cert`/`--cert-key`, `--cert-pfx`, or `--dev-cert` is required. `--cert` and `--cert-pfx` are mutually exclusive. HTTPS is mandatory — the server refuses to start without TLS configuration.

**One of `--key` or `--key-pfx` is required. They are mutually exclusive. When no signing key is provided, an ephemeral key is generated (development only).

The server signing key (`--key` or `--key-pfx`) is an ECDSA key used to sign Merkle tree checkpoints. Generate one with:

```
sigil generate -o server-signing
```

### Database providers

**SQLite** (default) — zero-configuration, single-file database:

```
dotnet run --project src/Sigil.LogServer -- --dev-cert --db sigil-log.db --key server.pem --api-key secret
```

**SQL Server** — for enterprise deployments:

```
dotnet run --project src/Sigil.LogServer -- --dev-cert --db-provider sqlserver \
  --connection-string "Server=localhost;Database=sigil_log;Trusted_Connection=True;" \
  --key server.pem --api-key secret
```

**PostgreSQL** — for cloud-native deployments:

```
dotnet run --project src/Sigil.LogServer -- --dev-cert --db-provider postgres \
  --connection-string "Host=localhost;Database=sigil_log;Username=sigil;Password=pass;" \
  --key server.pem --api-key secret
```

All providers create tables automatically on first start. The schema is provider-agnostic — the same logical structure is used across all three.

### mTLS (mutual TLS)

For environments requiring client certificate authentication (defense-in-depth on top of API keys):

```
dotnet run --project src/Sigil.LogServer -- \
  --cert server.crt \
  --cert-key server.key \
  --mtls-ca ca.pem \
  --db sigil-log.db \
  --key server.pem \
  --api-key secret
```

When `--mtls-ca` is set, the server requires clients to present a certificate signed by the specified CA. Both mTLS and API key are checked — either one failing rejects the request.

### Querying the log server

The server exposes read-only endpoints without authentication:

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/log/entries?limit=N&offset=M` | List entries (paginated) |
| GET | `/api/v1/log/entries/{index}` | Get a single entry |
| POST | `/api/v1/log/search` | Search by keyId, artifact name, or digest |
| GET | `/api/v1/log/checkpoint` | Get the current signed checkpoint |
| GET | `/api/v1/log/proof/inclusion/{index}` | Get an inclusion proof for an entry |
| GET | `/api/v1/log/proof/consistency?oldSize=N` | Get a consistency proof |
| GET | `/api/v1/log/publicKey` | Get the server's signing public key |

Write operations require the `X-Api-Key` header:

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/v1/log/entries` | `X-Api-Key` | Submit a new log entry |

### Rekor integration

Submit signatures to [Sigstore Rekor](https://rekor.sigstore.dev) instead of a self-hosted server:

```
sigil sign release.tar.gz --key mykey.pem --log-url rekor
```

This submits a `hashedrekord` entry to the public Rekor instance at `https://rekor.sigstore.dev`. No API key is needed.

For a self-hosted Rekor instance:

```
sigil sign release.tar.gz --key mykey.pem --log-url rekor:https://rekor.internal.example.com
```

The `rekor:` prefix tells Sigil to use the Rekor API format instead of the Sigil server format.

### How remote logging works

**Post-sign submission.** After signing (and optional timestamping), Sigil submits the signature entry and subject descriptor to the remote log. The log server:

1. Creates a leaf hash from the entry data (same `SHA-256(0x00 || data)` domain separation as the local log)
2. Appends the entry to its database
3. Recomputes the Merkle root over all entries
4. Signs a checkpoint (tree size + root hash + timestamp) with the server's ECDSA key
5. Returns a transparency receipt: log index, signed checkpoint, and inclusion proof

**Inclusion proofs.** The receipt includes a Merkle inclusion proof — a list of sibling hashes that, combined with the leaf hash, reconstruct the root hash. This lets a verifier confirm the entry is in the log without downloading all entries.

**Checkpoint signing.** The checkpoint payload is JCS-canonicalized (RFC 8785) before signing. The signature is appended to the base64-encoded checkpoint JSON, separated by a dot. Verifiers with the log's public key can cryptographically verify the checkpoint hasn't been tampered with.

**Duplicate detection.** Each entry includes a SHA-256 digest of the signature bytes. The same signature cannot be logged twice.

### Transparency receipt format

The transparency fields on a `SignatureEntry` after remote logging:

```json
{
  "transparencyLogUrl": "https://log.example.com",
  "transparencyLogIndex": 42,
  "transparencySignedCheckpoint": "eyJyb290SGFzaCI6Ii4uLiIsInRpbWVzdGFtcCI6Ii4uLiIsInRyZWVTaXplIjo0Mn0uPHNpZ25hdHVyZT4=",
  "transparencyInclusionProof": {
    "leafIndex": 42,
    "treeSize": 100,
    "rootHash": "a1b2c3d4e5f6...",
    "hashes": [
      "1111111111111111...",
      "2222222222222222...",
      "3333333333333333..."
    ]
  }
}
```

The `transparencySignedCheckpoint` is a base64-encoded string containing the JSON checkpoint payload followed by a dot and the ECDSA signature. The `hashes` array in the inclusion proof contains the sibling hashes needed to reconstruct the Merkle root from the leaf.

All transparency fields are nullable and omitted from the JSON when not present (`WhenWritingNull`). Existing envelopes without transparency fields continue to verify normally.

## Git commit signing

Sigil integrates with git as a drop-in signing program. Git commits and tags are signed with full Sigil envelopes — self-contained verification, multi-algorithm support, and the same key infrastructure used for file signing. No GPG installation required.

### Configure git to use Sigil

Generate a key and configure git to use it:

```
sigil generate -o mykey
sigil git config --key mykey.pem
```

```
Git signing configured with Sigil.
  Key: sha256:c017446b9040d...
  Wrapper: /home/user/.sigil/git-sign.sh
  Scope: local
  Tip: Use -S flag to sign commits, or run with --global to sign all commits.
```

This sets three git config values:
- `gpg.format = x509`
- `gpg.x509.program` = path to a wrapper script in `~/.sigil/`
- `user.signingkey` = your key fingerprint

To sign all commits automatically:

```
sigil git config --key mykey.pem --global
```

With `--global`, `commit.gpgsign = true` is also set, so every commit is signed without needing `-S`.

### Sign with a vault key (no private key on disk)

Configure git to sign commits using a vault provider. The private key never touches disk — it stays in the vault or hardware token:

```
sigil git config --vault hashicorp --vault-key transit/my-signing-key
```

```
Git signing configured with Sigil.
  Key: sha256:7f2a3b...
  Wrapper: /home/user/.sigil/git-sign.sh
  Scope: local
```

This works with all vault providers:

```
sigil git config --vault azure --vault-key my-signing-key --global
sigil git config --vault aws --vault-key alias/my-signing-key --global
sigil git config --vault gcp --vault-key projects/p/locations/us/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1 --global
sigil git config --vault pkcs11 --vault-key "pkcs11:token=YubiKey;object=my-key" --global
```

Vault authentication uses environment variables at commit time (not stored in the wrapper script). See [Vault-backed signing](#vault-backed-signing) for setup details per provider.

**Note:** If your PKCS#11 device requires touch-to-sign (e.g., YubiKey),
the terminal will pause after `git commit` and display "Waiting for PKCS#11
device (touch may be required)...". Touch your device to complete the signing.

### Sign with a PFX key

Configure git to sign commits using a PFX/PKCS#12 file:

```
sigil git config --key signing-cert.pfx --passphrase "pfx-password" --global
```

Sigil auto-detects the `.pfx` or `.p12` extension and extracts the signing key. The PFX passphrase is embedded in the wrapper script (see security note below).

### Sign with the Windows Certificate Store

Configure git to sign commits using a certificate from the Windows Certificate Store — the private key never touches disk:

```
sigil git config --cert-store abc123def456... --global
```

```
Git signing configured with Sigil.
  Key: sha256:7f2a3b...
  Wrapper: C:\Users\you\.sigil\git-sign.ps1
  Scope: global
  Mode: certificate store
```

Use `--store-location LocalMachine` for certificates installed in the machine store:

```
sigil git config --cert-store abc123def456... --store-location LocalMachine --global
```

This is ideal for enterprise environments where keys are managed via Active Directory or Group Policy.

### Sign with an encrypted PEM key

If your PEM key is passphrase-protected, configure git as usual:

```
sigil git config --key mykey.pem --global
```

Sigil resolves the passphrase at signing time using the [resolution chain](#resolution-chain). The passphrase is never embedded in the wrapper script.

**On Windows (recommended)**: Store the passphrase in Windows Credential Manager for seamless signing:

```
sigil credential store --key mykey.pem
```

After storing, git commits are signed without any passphrase prompts or environment variables.

**On Linux/macOS**: Set the passphrase in your shell profile:

```bash
# ~/.bashrc or ~/.zshrc
export SIGIL_PASSPHRASE="my secret"
```

```powershell
# PowerShell profile
$env:SIGIL_PASSPHRASE = "my secret"
```

**In CI/CD**: Use `--passphrase-file` or `SIGIL_PASSPHRASE_FILE` with a mounted secret:

```bash
export SIGIL_PASSPHRASE_FILE=/run/secrets/signing-passphrase
```

See [Passphrase and credential management](#passphrase-and-credential-management) for the full resolution chain and security recommendations.

### Sign commits and tags

Once configured, sign commits with the `-S` flag:

```
git commit -S -m "Signed commit"
```

Sign tags:

```
git tag -s v1.0 -m "Signed release"
```

With `--global` configuration, the `-S` and `-s` flags are not needed — all commits and tags are signed automatically.

### Verify commits

```
git verify-commit HEAD
```

```
git log --show-signature -1
```

Git displays `[GNUPG:]` status messages from Sigil:

```
[GNUPG:] NEWSIG
[GNUPG:] GOODSIG sha256:c017446b... sha256:c017446b...
[GNUPG:] VALIDSIG sha256:c017446b... 2026-02-09T14:30:00Z ecdsa-p256
[GNUPG:] TRUST_UNDEFINED 0 sigil
```

`TRUST_UNDEFINED` is emitted because git-sign performs cryptographic verification only — no trust bundle evaluation. The signature is valid, but trust decisions are left to the user.

Verify tags:

```
git verify-tag v1.0
```

### Wrapper script reference

`sigil git config` generates a thin wrapper script in `~/.sigil/` that forwards all arguments to `sigil git-sign`. You can also write these manually if you need custom behavior.

**PEM key (Unix)** — `~/.sigil/git-sign.sh`:

```bash
#!/bin/sh
exec "sigil" git-sign --key "/path/to/key.pem" "$@"
```

**PEM key (Windows)** — `%USERPROFILE%\.sigil\git-sign.bat`:

```batch
@"sigil" git-sign --key "C:\path\to\key.pem" %*
```

**Vault provider (Unix)** — `~/.sigil/git-sign.sh`:

```bash
#!/bin/sh
exec "sigil" git-sign --vault hashicorp --vault-key "transit/my-signing-key" "$@"
```

**Vault provider (Windows)** — `%USERPROFILE%\.sigil\git-sign.bat`:

```batch
@"sigil" git-sign --vault "hashicorp" --vault-key "transit/my-signing-key" %*
```

**PKCS#11 hardware token (Unix)** — `~/.sigil/git-sign.sh`:

```bash
#!/bin/sh
exec "sigil" git-sign --vault pkcs11 --vault-key "pkcs11:token=YubiKey;object=my-key" "$@"
```

After creating a wrapper script manually, configure git to use it:

```bash
# Unix
chmod +x ~/.sigil/git-sign.sh
git config --global gpg.format x509
git config --global gpg.x509.program ~/.sigil/git-sign.sh
git config --global user.signingkey "sha256:<your-key-fingerprint>"
git config --global commit.gpgsign true
```

```batch
:: Windows
git config --global gpg.format x509
git config --global gpg.x509.program "%USERPROFILE%\.sigil\git-sign.bat"
git config --global user.signingkey "sha256:<your-key-fingerprint>"
git config --global commit.gpgsign true
```

Get your key fingerprint from `sigil generate` output or by inspecting a signature envelope.

### How git signing works

**Git's signing protocol.** Git delegates signing to an external program via `gpg.x509.program`. For signing, git pipes the commit/tag object to stdin and expects an armored signature on stdout. For verification, git writes the signature to a temp file and pipes the original content to stdin.

**ASCII armor.** The signature stored in the git object is a Sigil envelope wrapped in ASCII armor:

```
-----BEGIN SIGNED MESSAGE-----
<base64-encoded Sigil SignatureEnvelope JSON>
-----END SIGNED MESSAGE-----
```

Inside the armor is a standard Sigil envelope — the same format used for file signing. The subject name is `git-object` (works for both commits and tags).

**Content normalization.** Git sends commit content with a blank line (`\n\n`) separating headers from the body during signing, but strips it during verification (the `gpgsig` header insertion consumes it). Sigil normalizes content by removing the first blank line in both paths, ensuring the digest matches regardless of which path git uses.

**GPG status protocol.** Git's `verify_gpg_signed_buffer` parses GPG-format status messages on the status file descriptor. Sigil emits `NEWSIG`, `GOODSIG`/`BADSIG`, `VALIDSIG`, and `TRUST_UNDEFINED` in the order git expects. The `NEWSIG` line is required by git 2.52+ — without the preceding newline, git's `strstr` check for `"\n[GNUPG:] GOODSIG"` fails.

**GPG argument compatibility.** Git passes GPG-style arguments (`--status-fd=2 -bsau <keyid>`) that don't conform to standard CLI conventions. Sigil intercepts these before its normal command parser and handles them with custom argument parsing.

**Self-contained verification.** Like all Sigil signatures, the public key is embedded in the envelope. Verification uses the existing `SignatureValidator` — no separate key import or key server lookup needed.

## Container/OCI image signing

Sigil signs OCI container images directly in the registry. Signatures are stored as OCI 1.1 artifacts using the referrers API, making them discoverable by any compliant registry. Unlike Cosign, Sigil requires no cloud infrastructure — offline verification works with the same self-contained envelopes used for file signing.

Zero new dependencies — BCL `HttpClient` + `System.Text.Json` only.

### Sign a container image

Sign an image in any OCI 1.1-compatible registry:

```
sigil sign-image ghcr.io/myorg/myapp:v1.0 --key mykey.pem
```

```
Signed: ghcr.io/myorg/myapp:v1.0
Digest: sha256:a1b2c3d4...
Algorithm: ecdsa-p256
Key: sha256:c017446b...
Mode: persistent key
Signature: sha256:e5f6a7b8...
```

All signing modes work — ephemeral, persistent, vault, and PKCS#11:

```
sigil sign-image registry.example.com/app:latest
sigil sign-image registry.example.com/app:latest --key mykey.pem
sigil sign-image registry.example.com/app:latest --vault aws --vault-key alias/ci-key
sigil sign-image registry.example.com/app:latest --vault pkcs11 --vault-key "pkcs11:token=YubiKey;object=my-key"
```

Add a label and timestamp:

```
sigil sign-image ghcr.io/myorg/myapp:v1.0 --key mykey.pem --label "ci-build" --timestamp http://timestamp.digicert.com
```

Each `sign-image` invocation creates a separate OCI artifact. Multiple parties can sign the same image independently — all signatures are discoverable via referrers.

**Multi-arch images:** `sign-image` signs whatever the tag resolves to — whether that's a single manifest or a manifest list (OCI image index). This matches Cosign's behavior.

### Verify a container image

```
sigil verify-image ghcr.io/myorg/myapp:v1.0
```

```
Image: ghcr.io/myorg/myapp:v1.0
Digest: sha256:a1b2c3d4...
Signatures: 2

  [VERIFIED] Signature #1
    Key: sha256:c01744...
    Algorithm: ecdsa-p256
    Label: ci-build
    Timestamp: 2026-02-09T14:30:00Z
  [VERIFIED] Signature #2
    Key: sha256:7f2a3b...
    Algorithm: ecdsa-p384

All signatures VERIFIED.
```

Trust bundles, policies, and discovery all work:

```
sigil verify-image ghcr.io/myorg/myapp:v1.0 --trust-bundle trust-signed.json --authority sha256:def456...
sigil verify-image ghcr.io/myorg/myapp:v1.0 --discover example.com
sigil verify-image ghcr.io/myorg/myapp:v1.0 --policy policy.json
```

### Registry authentication

Sigil resolves registry credentials automatically, in this order:

1. **Environment variables** — `SIGIL_REGISTRY_USERNAME` and `SIGIL_REGISTRY_PASSWORD`
2. **Docker credential helpers** — per-registry helpers from `~/.docker/config.json` `credHelpers`
3. **Docker credential store** — default helper from `~/.docker/config.json` `credsStore`
4. **Docker config auths** — base64-encoded credentials from `~/.docker/config.json` `auths`
5. **Anonymous** — no authentication

If you're already authenticated with `docker login`, Sigil uses those credentials automatically. For CI/CD, set the environment variables:

```bash
# Linux / macOS
export SIGIL_REGISTRY_USERNAME=myuser
export SIGIL_REGISTRY_PASSWORD=mytoken

# Windows (PowerShell)
$env:SIGIL_REGISTRY_USERNAME = "myuser"
$env:SIGIL_REGISTRY_PASSWORD = "mytoken"

# Windows (cmd)
set SIGIL_REGISTRY_USERNAME=myuser
set SIGIL_REGISTRY_PASSWORD=mytoken
```

**Token auth** is handled transparently. When a registry returns a 401 with a `Www-Authenticate: Bearer` challenge, Sigil requests a token from the auth endpoint and caches it for subsequent requests.

### How container signing works

**Sign flow:**

1. Parse the image reference (e.g., `ghcr.io/myorg/myapp:v1.0`)
2. `HEAD /v2/<repo>/manifests/<tag>` — get the manifest digest, size, and media type
3. `GET /v2/<repo>/manifests/<digest>` — fetch the manifest bytes (the artifact being signed)
4. Build a `SubjectDescriptor` with `name=<full image ref>`, `digests=SHA-256+SHA-512(manifest bytes)`, `mediaType=<manifest media type>`
5. Build the signing payload (same as file signing: JCS subject + SHA-256 digest + JCS signed attributes)
6. Sign with the signer (ephemeral, PEM, vault, or PKCS#11)
7. Optionally apply RFC 3161 timestamp
8. Upload the signature envelope as a blob (`POST` + `PUT /v2/<repo>/blobs/uploads/`)
9. Push a signature manifest with `subject` pointing to the signed image (`PUT /v2/<repo>/manifests/<digest>`)

**Verify flow:**

1. Parse the image reference
2. `HEAD /v2/<repo>/manifests/<tag>` — get the manifest digest
3. `GET /v2/<repo>/referrers/<digest>?artifactType=application/vnd.sigil.signature.v1+json` — find Sigil signatures
4. For each signature artifact: fetch the manifest, fetch the layer blob, deserialize the `SignatureEnvelope`
5. `GET /v2/<repo>/manifests/<digest>` — fetch the signed manifest bytes
6. Verify each signature against the manifest bytes (same as file verification)
7. Optionally evaluate trust bundles, policies, or discovery

**HTTPS enforcement:** All registry communication uses HTTPS, except for `localhost`, `127.0.0.1`, and `::1` (which use HTTP for local development registries).

### Signature storage format

Signatures are stored as OCI artifact manifests per the OCI 1.1 spec:

```json
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "artifactType": "application/vnd.sigil.signature.v1+json",
  "config": {
    "mediaType": "application/vnd.oci.empty.v1+json",
    "digest": "sha256:44136fa355b311bfa706c3dba8b08a9b3bb45c4c5d86a99e340f0a2b9df3ac36",
    "size": 2
  },
  "layers": [
    {
      "mediaType": "application/vnd.sigil.signature.v1+json",
      "digest": "sha256:<envelope-digest>",
      "size": 1234
    }
  ],
  "subject": {
    "mediaType": "application/vnd.oci.image.manifest.v1+json",
    "digest": "sha256:<image-manifest-digest>",
    "size": 5678
  }
}
```

The `subject` field links the signature to the signed image. Registries index this relationship via the referrers API, making signatures discoverable. The `layers[0]` blob contains a standard Sigil `SignatureEnvelope` — the same format used for file signatures.

The `config` is the OCI empty descriptor (`{}`, 2 bytes) — required by the spec but unused for signature artifacts.

**Compatible registries:** Any OCI 1.1-compliant registry that supports the referrers API. This includes GitHub Container Registry (ghcr.io), Docker Hub, Azure Container Registry, Amazon ECR, Google Artifact Registry, and Harbor 2.6+.

## Batch/manifest signing

Sigil signs multiple files in one operation with a shared manifest signature. A single `.manifest.sig.json` file covers every file — adding, removing, reordering, or tampering with any file invalidates the signature.

Zero new dependencies — reuses existing signing, verification, and trust infrastructure.

### Sign multiple files

Sign all files in a directory:

```
sigil sign-manifest ./release/ --key mykey.pem
```

```
Manifest signed: 4 files
Algorithm: ecdsa-p256
Key: sha256:c017446b...
Mode: persistent key
Output: release/manifest.sig.json
```

All signing modes work — ephemeral, persistent, vault, and PKCS#11:

```
sigil sign-manifest ./release/
sigil sign-manifest ./release/ --key mykey.pem
sigil sign-manifest ./release/ --vault aws --vault-key alias/ci-key
sigil sign-manifest ./release/ --vault pkcs11 --vault-key "pkcs11:token=YubiKey;object=my-key"
```

Add a label and timestamp:

```
sigil sign-manifest ./release/ --key mykey.pem --label "ci-build" --timestamp http://timestamp.digicert.com
```

Specify a custom output path:

```
sigil sign-manifest ./release/ --key mykey.pem --output dist/manifest.sig.json
```

### Verify a manifest

```
sigil verify-manifest release/manifest.sig.json
```

```
Manifest: manifest.sig.json (4 files)
  [OK] README.md
  [OK] src/components/Button.cs
  [OK] src/utils/Format.cs
  [OK] tests/Test.cs

Signatures:
  [VERIFIED] sha256:c017446b...

All signatures VERIFIED.
```

Default base path is the manifest file's directory. Override with `--base-path`:

```
sigil verify-manifest manifest.sig.json --base-path ./release/
```

If any file has been tampered with:

```
Manifest: manifest.sig.json (4 files)
  [OK] README.md
  [FAIL] src/components/Button.cs — Digest mismatch.
  [OK] src/utils/Format.cs
  [OK] tests/Test.cs

Signatures:
  [VERIFIED] sha256:c017446b...

VERIFICATION FAILED.
```

### Filter files with --include

Sign only specific file types:

```
sigil sign-manifest ./release/ --include "*.dll" --key mykey.pem
```

```
Manifest signed: 3 files
```

Without `--include`, all files in the directory (recursive) are signed.

### Multiple manifest signatures

Each `sign-manifest` invocation to an existing manifest appends a new signature:

```
sigil sign-manifest ./release/ --key alice.pem
sigil sign-manifest ./release/ --key bob.pem --output release/manifest.sig.json
```

The second invocation loads the existing manifest and appends Bob's signature. Both signatures are verified independently.

### Manifests with trust bundles

Trust bundles, policies, and discovery all work with manifests:

```
sigil verify-manifest release/manifest.sig.json --trust-bundle trust-signed.json --authority sha256:def456...
sigil verify-manifest release/manifest.sig.json --discover example.com
sigil verify-manifest release/manifest.sig.json --policy policy.json
```

### How manifest signing works

**Sign flow:**

1. Enumerate all files under the base directory (recursive), applying `--include` filter if specified
2. Sort files by forward-slash-separated relative path (`StringComparer.Ordinal`) for deterministic ordering
3. For each file: compute SHA-256 and SHA-512 digests, auto-detect SBOM format (CycloneDX/SPDX), build a `SubjectDescriptor`
4. Build the signing payload: `JCS(subjects-array) + JCS(signed-attributes)` — digests are embedded in each subject, not hashed separately
5. Sign the payload (ephemeral, PEM, vault, or PKCS#11)
6. Optionally apply RFC 3161 timestamp
7. Write the manifest envelope to `.manifest.sig.json`

**Verify flow:**

1. Load the manifest envelope from `.manifest.sig.json`
2. For each subject: resolve relative path against base directory, read file, compute digests, compare against envelope
3. Path traversal protection: reject subject names that resolve outside the base directory
4. For each signature: rebuild the signing payload from the subjects array and verify against the embedded public key
5. Optionally evaluate trust bundles, policies, or discovery

**Key property:** The subjects array is covered by the signature. Any change — adding a file, removing a file, reordering files, or modifying a single byte — invalidates all signatures.

### Manifest envelope format

The `.manifest.sig.json` envelope:

```json
{
  "version": "1.0",
  "kind": "manifest",
  "subjects": [
    {
      "digests": {
        "sha256": "f12c1087...",
        "sha512": "9a39f53e..."
      },
      "name": "README.md"
    },
    {
      "digests": {
        "sha256": "a6c43afd...",
        "sha512": "3d80c16d..."
      },
      "name": "src/components/Button.cs"
    }
  ],
  "signatures": [
    {
      "keyId": "sha256:c017446b...",
      "algorithm": "ecdsa-p256",
      "publicKey": "MFkwEwYH...",
      "value": "N6Nx/spZ...",
      "timestamp": "2026-02-10T10:13:15Z"
    }
  ]
}
```

The `kind` field distinguishes manifest envelopes from single-file envelopes (`"artifact"`). Subjects are ordered deterministically by name. Each signature covers the entire subjects array — there are no per-file signatures.

## Archive signing

Sigil signs archives (ZIP, tar.gz, tar) with per-entry digest verification. A single `.archive.sig.json` file contains SHA-256 and SHA-512 digests for every entry inside the archive, plus one or more cryptographic signatures. Recipients can verify archive integrity and authenticity without extracting the archive first.

Zero new dependencies — reuses existing `ManifestEnvelope` infrastructure with `kind = "archive"`.

Supported formats:
- **ZIP** (`.zip`) — including `.nupkg` NuGet packages
- **tar.gz / .tgz** — gzip-compressed tar archives
- **tar** — uncompressed tar archives

Format is detected by magic bytes with file extension as fallback.

### Sign an archive file

```
sigil sign-archive release.zip --key mykey.pem
```

```
Archive signed: 12 entries
Algorithm: ecdsa-p256
Key: sha256:c017446b...
Mode: persistent key
Output: release.zip.archive.sig.json
```

All signing modes work — ephemeral, persistent, vault, cert store, and PKCS#11:

```
sigil sign-archive release.zip
sigil sign-archive release.zip --key mykey.pem
sigil sign-archive release.tar.gz --vault aws --vault-key alias/ci-key
sigil sign-archive release.zip --cert-store ABC123
```

Add a label and timestamp:

```
sigil sign-archive release.zip --key mykey.pem --label "v2.1.0" --timestamp http://timestamp.digicert.com
```

Specify a custom output path:

```
sigil sign-archive release.zip --key mykey.pem --output dist/release.sig.json
```

### Verify an archive

```
sigil verify-archive release.zip
```

```
Archive: release.zip (12 entries)
  [OK] lib/MyLib.dll
  [OK] lib/MyLib.pdb
  [OK] sbom.cdx.json (CycloneDX 1.5)
  ...

Signatures:
  [VERIFIED] sha256:c017446b...

All signatures VERIFIED.
```

Default signature path is `<archive>.archive.sig.json`. Override with `--signature`:

```
sigil verify-archive release.zip --signature dist/release.sig.json
```

Trust bundles, policies, and discovery all work with archives:

```
sigil verify-archive release.zip --trust-bundle trust-signed.json --authority sha256:def456...
sigil verify-archive release.zip --discover example.com
sigil verify-archive release.zip --policy policy.json
```

### Tampered entry detection

If any entry has been modified since signing:

```
Archive: release.zip (12 entries)
  [OK] lib/MyLib.dll
  [FAIL] lib/MyLib.pdb — Digest mismatch.
  [OK] sbom.cdx.json (CycloneDX 1.5)
  ...

Signatures:
  [VERIFIED] sha256:c017446b...

VERIFICATION FAILED.
```

Digest mismatch is reported per-entry, even when the overall signature is still cryptographically valid (the signature covers the original digests, not the current file contents).

### Extra entry detection

Entries present in the archive but not covered by the envelope are reported as warnings:

```
Archive: release.zip (13 entries)
  [OK] lib/MyLib.dll
  ...

Extra entries (not in envelope):
  debug.log

Signatures:
  [VERIFIED] sha256:c017446b...

All signatures VERIFIED.
WARNING: 1 extra entry not covered by envelope.
```

Extra entries do not cause verification failure but indicate the archive has been modified since signing.

### NuGet package metadata

When signing `.nupkg` files, Sigil extracts metadata from the embedded `.nuspec`:

```
sigil sign-archive MyLib.1.0.0.nupkg --key mykey.pem
```

The envelope's subjects include NuGet-specific metadata:

```json
{
  "name": "MyLib.nuspec",
  "metadata": {
    "nuget.id": "MyLib",
    "nuget.version": "1.0.0",
    "nuget.authors": "Alice"
  }
}
```

### How archive signing works

**Sign flow:**

1. Detect archive format (ZIP, tar.gz, tar) by magic bytes or file extension
2. Iterate all entries, skipping directories
3. For each entry: stream content with a 500 MB per-entry size limit (zip bomb protection), compute SHA-256 and SHA-512 digests, auto-detect SBOM format (CycloneDX/SPDX), build a `SubjectDescriptor`
4. For `.nupkg` archives: extract `.nuspec` metadata (package id, version, authors)
5. Sort subjects by forward-slash normalized path (`StringComparer.Ordinal`) for deterministic ordering
6. Build the signing payload: `JCS(subjects-array) + JCS(signed-attributes)` — same as manifest signing
7. Sign the payload (ephemeral, PEM, PFX, vault, cert store, or PKCS#11)
8. Optionally apply RFC 3161 timestamp and/or submit to transparency log
9. Write the archive envelope to `.archive.sig.json`

**Verify flow:**

1. Load the archive envelope from `.archive.sig.json`
2. Detect archive format and re-read all entries
3. For each subject in the envelope: find the matching entry in the archive, recompute digests, compare
4. Report entries in the archive not covered by the envelope (extra entries)
5. For each signature: rebuild the signing payload from the subjects array and verify against the embedded public key
6. Optionally evaluate trust bundles, policies, or discovery

**Security:**
- Path traversal protection: entries with `..` path segments or absolute paths are rejected
- Zip bomb protection: 500 MB per-entry size limit enforced during streaming
- Archives within archives are treated as opaque entries (no recursive opening)

### Archive envelope format

The `.archive.sig.json` envelope:

```json
{
  "version": "1.0",
  "kind": "archive",
  "subjects": [
    {
      "digests": {
        "sha256": "f12c1087...",
        "sha512": "9a39f53e..."
      },
      "name": "lib/MyLib.dll"
    },
    {
      "digests": {
        "sha256": "b5bed928...",
        "sha512": "cb529285..."
      },
      "name": "sbom.cdx.json",
      "mediaType": "application/vnd.cyclonedx+json",
      "metadata": {
        "sbom.format": "CycloneDX",
        "sbom.specVersion": "1.5",
        "sbom.componentCount": "42"
      }
    }
  ],
  "signatures": [
    {
      "keyId": "sha256:c017446b...",
      "algorithm": "ecdsa-p256",
      "publicKey": "MFkwEwYH...",
      "value": "N6Nx/spZ...",
      "timestamp": "2026-02-11T15:30:00Z"
    }
  ]
}
```

The `kind` field is `"archive"` (vs `"manifest"` for directory signing or `"artifact"` for single files). Subjects are ordered deterministically by name. Each signature covers the entire subjects array.

## Authenticode PE signing

Sigil embeds standard [Authenticode](https://learn.microsoft.com/en-us/windows/win32/seccrypto/authenticode) signatures directly in Windows PE binaries (.exe, .dll). This gives you OS-level trust: SmartScreen recognition, UAC publisher display, and enterprise deployment compatibility. Alongside the embedded Authenticode signature, Sigil produces a detached `.sig.json` envelope so you can apply trust bundles, policies, and discovery — the same verification model as every other Sigil artifact type.

**Key facts:**
- Pure managed, cross-platform — works on Linux CI signing Windows binaries
- PFX/P12 or Windows Certificate Store only (Authenticode requires X.509 certificates; PEM keys are rejected)
- SHA-256 only (no SHA-1)
- Dual output: embedded Authenticode PKCS#7 in the PE + detached `.sig.json` Sigil envelope
- Zero new dependencies

### Sign a PE binary

```
sigil sign-pe app.exe --key codesigning.pfx --passphrase "changeit"
```

```
PE signed: app.exe
Subject: CN=My Company
Thumbprint: ABC123DEF456...
Output: app.exe
Envelope: app.exe.sig.json
```

Two signing modes are available — PFX file or Windows Certificate Store:

```
sigil sign-pe app.exe --key codesigning.pfx
sigil sign-pe app.exe --cert-store ABC123DEF456 --store-location CurrentUser
```

Add a label and RFC 3161 timestamp (timestamps both the Authenticode signature and the Sigil envelope):

```
sigil sign-pe app.dll --key codesigning.pfx --label "v3.0.0" --timestamp http://timestamp.digicert.com
```

Write signed PE to a different path instead of overwriting in-place:

```
sigil sign-pe app.exe --key codesigning.pfx --output signed/app.exe
```

Override the envelope output path:

```
sigil sign-pe app.exe --key codesigning.pfx --envelope dist/app.sig.json
```

### Verify a PE binary

```
sigil verify-pe app.exe
```

```
PE file: app.exe

Authenticode:
  [VERIFIED] Authenticode signature is valid
  Subject: CN=My Company
  Issuer: CN=My CA
  Thumbprint: ABC123DEF456...
  Digest: SHA256
  Timestamp: 2026-02-11T15:30:00Z

Sigil envelope:
  [VERIFIED] sha256:c017446b...

  All envelope signatures VERIFIED.
```

Default envelope path is `<pe-file>.sig.json`. Override with `--signature`:

```
sigil verify-pe app.exe --signature dist/app.sig.json
```

Trust bundles, policies, and discovery all work with PE verification:

```
sigil verify-pe app.exe --trust-bundle trust-signed.json --authority sha256:def456...
sigil verify-pe app.exe --discover example.com
sigil verify-pe app.exe --policy policy.json
```

### Tampered PE detection

If the PE binary has been modified after signing:

```
PE file: app.exe

Authenticode:
  [FAILED] Authenticode digest mismatch.

Sigil envelope:
  [VERIFIED] sha256:c017446b...
           Artifact digest mismatch.

  Envelope signature verification FAILED.
```

The Authenticode check and Sigil envelope check are independent. A byte-level modification in the PE will fail both, but a corruption of just the `.sig.json` file will only affect the envelope verification.

### Dual-signature model

PE signing produces two signatures:

| Signature | Location | Covers | Used by |
|-----------|----------|--------|---------|
| Authenticode PKCS#7 | Embedded in PE Certificate Table | PE headers + sections (excluding cert table) | Windows OS, SmartScreen, UAC, enterprise GPO |
| Sigil `.sig.json` | Detached file | Entire signed PE (including embedded Authenticode) | Sigil trust bundles, policies, discovery |

The Sigil envelope digests are computed over the **signed** PE (after the Authenticode signature is embedded). This means the envelope protects the Authenticode signature itself — stripping or replacing the Authenticode signature will fail Sigil verification.

### How Authenticode PE signing works

**Sign flow:**

1. Parse the PE (MZ signature, PE\0\0, COFF header, Optional Header, section headers)
2. Strip any existing Certificate Table (for re-signing)
3. Compute the Authenticode hash: SHA-256 over headers + sections, excluding the CheckSum field (4 bytes), Certificate Table directory entry (8 bytes), and certificate data
4. Build an `SpcIndirectDataContent` structure (ASN.1 DER) containing the digest
5. Create a CMS/PKCS#7 `SignedData` with the SpcIndirectData as content
6. Build a `WIN_CERTIFICATE` structure (revision 0x0200, type 0x0002) and 8-byte align
7. Append to PE, update Certificate Table directory entry (file offset + size)
8. Recompute and write the PE checksum (16-bit fold-and-carry + file length)
9. If `--timestamp` is provided, apply RFC 3161 timestamp to both the Authenticode PKCS#7 and the Sigil envelope
10. Produce the detached `.sig.json` envelope from the signed PE bytes

**Verify flow:**

1. Parse the PE and extract the Certificate Table
2. Decode the CMS/PKCS#7 `SignedData` from the `WIN_CERTIFICATE`
3. Recompute the Authenticode hash (same exclusion rules as signing)
4. Compare the recomputed digest with the digest embedded in `SpcIndirectDataContent`
5. Verify the CMS signature cryptographically (`CheckSignature`)
6. Extract certificate info (subject, issuer, thumbprint) and any RFC 3161 timestamp
7. If a `.sig.json` envelope exists, verify it independently (same as `sigil verify`)
8. Optionally evaluate trust bundles, policies, or discovery

**Security:**
- 500 MB file size limit to prevent unbounded memory allocation
- uint32 overflow checks on all PE section and Certificate Table bounds
- PE parsing reads headers only — no code execution
- PFX bytes are zeroed after loading (`CryptographicOperations.ZeroMemory`)
- Constant-time digest comparison (`CryptographicOperations.FixedTimeEquals`)

## Keyless/OIDC signing

Keyless signing lets you sign artifacts using your CI identity (GitHub Actions, GitLab CI, etc.) without managing any keys. An ephemeral key pair is generated, bound to your OIDC token, and discarded after signing. The OIDC token is embedded in the signature envelope so verifiers can confirm who signed it.

### Sign in GitHub Actions

In a GitHub Actions workflow, Sigil auto-detects the OIDC environment:

```yaml
- name: Sign artifact
  run: sigil sign artifact.tar.gz --keyless --timestamp https://freetsa.org/tsr
```

The `--timestamp` flag is required for keyless signing — ephemeral keys need timestamps for trust evaluation. Sigil requests a token from GitHub's OIDC provider, binds it to the ephemeral key via the `aud` claim, signs the artifact, and embeds the JWT in the envelope.

### Sign in GitLab CI

In a GitLab CI pipeline, configure an `id_token` with audience `sigil` and Sigil auto-detects the `SIGIL_ID_TOKEN` environment variable:

```yaml
# .gitlab-ci.yml
sign:
  id_tokens:
    SIGIL_ID_TOKEN:
      aud: sigil
  script:
    - sigil sign artifact.tar.gz --keyless --timestamp https://freetsa.org/tsr
```

GitLab CI tokens have a fixed audience set in `.gitlab-ci.yml` (no runtime API for dynamic audiences). Sigil accepts `aud: sigil` as a valid generic audience during verification.

### Sign with a manual OIDC token

For other OIDC providers or testing, pass the token directly:

```
sigil sign artifact.tar.gz --keyless --oidc-token <jwt> --timestamp https://freetsa.org/tsr
```

### Trust OIDC identities

Add trusted OIDC identities to a trust bundle:

```
sigil trust identity-add trust.json \
  --issuer https://token.actions.githubusercontent.com \
  --subject "repo:myorg/*" \
  --name "GitHub CI (myorg)"
```

<details>
<summary>PowerShell / cmd</summary>

```powershell
sigil trust identity-add trust.json `
  --issuer https://token.actions.githubusercontent.com `
  --subject "repo:myorg/*" `
  --name "GitHub CI (myorg)"
```

```batch
sigil trust identity-add trust.json ^
  --issuer https://token.actions.githubusercontent.com ^
  --subject "repo:myorg/*" ^
  --name "GitHub CI (myorg)"
```

</details>

For GitLab CI:

```
sigil trust identity-add trust.json \
  --issuer "https://gitlab.com" \
  --subject "project_path:myorg/myproject:*" \
  --name "GitLab CI"
```

<details>
<summary>PowerShell / cmd</summary>

```powershell
sigil trust identity-add trust.json `
  --issuer "https://gitlab.com" `
  --subject "project_path:myorg/myproject:*" `
  --name "GitLab CI"
```

```batch
sigil trust identity-add trust.json ^
  --issuer "https://gitlab.com" ^
  --subject "project_path:myorg/myproject:*" ^
  --name "GitLab CI"
```

</details>

The `--subject` supports glob patterns — `repo:myorg/*` trusts any repository in the `myorg` organization (GitHub), `project_path:myorg/myproject:*` trusts any ref in a GitLab project. The `--issuer` must match exactly (no URL normalization).

Remove an identity:

```
sigil trust identity-remove trust.json \
  --issuer https://token.actions.githubusercontent.com \
  --subject "repo:myorg/*"
```

<details>
<summary>PowerShell / cmd</summary>

```powershell
sigil trust identity-remove trust.json `
  --issuer https://token.actions.githubusercontent.com `
  --subject "repo:myorg/*"
```

```batch
sigil trust identity-remove trust.json ^
  --issuer https://token.actions.githubusercontent.com ^
  --subject "repo:myorg/*"
```

</details>

### Verify keyless signatures

Verification works the same as regular signatures. When a trust bundle contains OIDC identities, Sigil fetches the issuer's JWKS to validate the embedded JWT:

```
sigil verify artifact.tar.gz --trust-bundle trust.json
```

Output includes OIDC identity info:

```
Artifact: artifact.tar.gz
Digests: MATCH
  [TRUSTED (OIDC)] sha256:abc123... (GitHub CI (myorg))
           OIDC: repo:myorg/myrepo:ref:refs/heads/main (from https://token.actions.githubusercontent.com)
           Timestamp: 2026-02-10T10:00:00Z (verified)

All signatures TRUSTED.
```

### How keyless signing works

1. **Generate ephemeral key** — Sigil creates a throwaway ECDSA P-256 key pair in memory.
2. **Compute audience** — The audience is `sigil:sha256:<SPKI-fingerprint>`, cryptographically binding the OIDC token to this specific key.
3. **Acquire OIDC token** — In GitHub Actions, Sigil calls the `ACTIONS_ID_TOKEN_REQUEST_URL` API with the audience. In GitLab CI, Sigil reads the pre-configured `SIGIL_ID_TOKEN` environment variable. For manual mode, the user provides the token directly.
4. **Sign artifact** — The ephemeral key signs the artifact using the same payload format as regular signatures.
5. **Embed OIDC metadata** — The signature entry includes `oidcToken` (the raw JWT), `oidcIssuer`, and `oidcIdentity` fields.
6. **Apply timestamp** — An RFC 3161 timestamp is mandatory for keyless signatures.
7. **Discard key** — The ephemeral private key is discarded after signing.

During verification:
1. **Parse JWT** — Extract issuer, subject, audience, and key ID from the embedded JWT.
2. **Fetch JWKS** — Retrieve the issuer's public keys via `{issuer}/.well-known/openid-configuration` → `jwks_uri`.
3. **Verify JWT signature** — Validate the JWT using the matching JWK (RS256 or ES256).
4. **Check audience binding** — Confirm the JWT's `aud` matches `sigil:sha256:<SPKI-fingerprint>` of the signing key, or the generic audience `sigil` (accepted during verification to support providers like GitLab CI that use fixed audiences).
5. **Evaluate trust** — Match the JWT's issuer and subject against the trust bundle's `identities` list using glob patterns.

The audience binding prevents token reuse: an OIDC token acquired for one ephemeral key cannot be replayed with a different key, because the audience contains the key's fingerprint. GitLab CI tokens use a generic `sigil` audience (no per-key binding), so security relies on short-lived tokens, issuer+subject identity matching in the trust bundle, and mandatory timestamps.

## PFX and certificate store signing

Sigil supports loading signing keys from PFX/PKCS#12 files and the Windows Certificate Store, in addition to PEM files and vault providers. These key sources are common in Windows enterprise environments, code signing workflows, and Active Directory-managed infrastructure.

### Sign with a PFX file

PFX (PKCS#12) files bundle a private key with its certificate chain in a single encrypted file. Sigil auto-detects PFX files by extension — pass a `.pfx` or `.p12` file to `--key` just like a PEM file:

```
sigil sign release.tar.gz --key code-signing.pfx --passphrase "my-password"
```

PFX files work everywhere `--key` is accepted:

```
sigil sign release.tar.gz --key cert.pfx --passphrase "pass"
sigil sign-manifest ./dist/ --key cert.pfx --passphrase "pass"
sigil sign-image ghcr.io/org/app:v1 --key cert.pfx --passphrase "pass"
sigil attest release.tar.gz --predicate prov.json --type slsa-provenance-v1 --key cert.pfx --passphrase "pass"
sigil trust sign trust.json --key cert.pfx --passphrase "pass"
sigil git config --key cert.pfx --passphrase "pass" --global
```

PFX files without a password also work:

```
sigil sign release.tar.gz --key unprotected.pfx
```

### PFX auto-detection

Sigil determines the key format by file extension:

| Extension | Format | How it's loaded |
|-----------|--------|-----------------|
| `.pem` | PEM | Parsed as PKCS#8, SEC1, or PKCS#1 |
| `.pfx` | PKCS#12 | Certificate + key extracted |
| `.p12` | PKCS#12 | Same as `.pfx` |
| `.PFX`, `.P12` | PKCS#12 | Case-insensitive |

The `--passphrase` option serves double duty: it decrypts encrypted PEM files **and** unlocks password-protected PFX files.

### PFX security

Sigil follows secure key handling practices when loading PFX files:

- **Ephemeral import**: Keys are imported with `EphemeralKeySet` — they never persist in the Windows certificate store
- **Memory zeroing**: PFX file bytes and extracted PKCS#8 DER bytes are zeroed with `CryptographicOperations.ZeroMemory` after use
- **No store pollution**: Temporary certificates are never installed in `CurrentUser\My` or `LocalMachine\My`

### Windows Certificate Store

The Windows Certificate Store provides centralized key management via `certmgr.msc`, Active Directory, Group Policy, and CNG/HSM-backed keys. Use `--cert-store` with a certificate's SHA-1 thumbprint:

```
sigil sign release.tar.gz --cert-store 1a2b3c4d5e6f7890abcdef1234567890abcdef12
```

Find a certificate's thumbprint in PowerShell:

```powershell
Get-ChildItem Cert:\CurrentUser\My | Format-Table Subject, Thumbprint
```

Or in `certmgr.msc`: open a certificate > Details tab > Thumbprint field.

**Store location**: By default, Sigil searches `CurrentUser\My`. For certificates installed in the machine store:

```
sigil sign release.tar.gz --cert-store 1a2b3c4d... --store-location LocalMachine
```

**Non-exportable keys**: When a certificate's private key is marked non-exportable (common for HSM-backed or CNG keys), Sigil uses `CertificateKeySigner` to sign through the certificate's crypto provider — the private key material is never extracted. `CanExportPrivateKey` returns `false` for these signers.

**Exportable keys**: When the private key is exportable, Sigil extracts the PKCS#8 DER and imports it into the standard signer infrastructure for maximum compatibility.

**Platform guard**: `--cert-store` is Windows-only. On other platforms, an error message is displayed immediately.

The `--cert-store` option works with all signing commands:

```
sigil sign release.tar.gz --cert-store abc123...
sigil sign-manifest ./dist/ --cert-store abc123...
sigil sign-image ghcr.io/org/app:v1 --cert-store abc123...
sigil attest release.tar.gz --predicate prov.json --type slsa-provenance-v1 --cert-store abc123...
sigil trust sign trust.json --cert-store abc123...
```

### Certificate store with git signing

Configure git to sign commits using a certificate from the store:

```
sigil git config --cert-store abc123def456... --global
```

Every `git commit` and `git tag -s` will sign using that certificate's key. Vault authentication and passphrase management are not needed — the Windows certificate store handles key access.

### LogServer with PFX keys

The Sigil LogServer accepts PFX files for both TLS and checkpoint signing:

```
dotnet run --project src/Sigil.LogServer -- \
  --cert-pfx server.pfx --cert-password "tls-pass" \
  --key-pfx signing.pfx --key-password "signing-pass" \
  --api-key secret --db sigil-log.db
```

This is useful in Windows environments where TLS certificates and signing keys are distributed as PFX files. PFX bytes are zeroed from memory after loading.

| LogServer option | Description |
|------------------|-------------|
| `--key-pfx` | PFX file for checkpoint signing (alternative to `--key`) |
| `--key-password` | Password for `--key-pfx` |
| `--cert-pfx` | PFX file for TLS (alternative to `--cert`/`--cert-key`) |
| `--cert-password` | Password for `--cert-pfx` |

`--key` and `--key-pfx` are mutually exclusive. `--cert`/`--cert-key` and `--cert-pfx` are mutually exclusive.

## Passphrase and credential management

When a PEM key is encrypted with a passphrase, Sigil resolves the passphrase from multiple sources in priority order. This applies to all signing commands (`sign`, `attest`, `sign-manifest`, `sign-image`, `trust sign`, `git config`, and `git-sign`).

### Resolution chain

Sigil checks these sources in order, using the first one that returns a value:

| Priority | Source | How to set |
|----------|--------|------------|
| 1 | `--passphrase` CLI argument | `sigil sign file.txt --key key.pem --passphrase "secret"` |
| 2 | `--passphrase-file` CLI argument | `sigil sign file.txt --key key.pem --passphrase-file /path/to/pass.txt` |
| 3 | `SIGIL_PASSPHRASE` environment variable | `export SIGIL_PASSPHRASE="secret"` |
| 4 | `SIGIL_PASSPHRASE_FILE` environment variable | `export SIGIL_PASSPHRASE_FILE=/path/to/pass.txt` |
| 5 | Windows Credential Manager | `sigil credential store --key key.pem` |
| 6 | Interactive console prompt | Prompted at runtime (if TTY is available) |

If no source provides a passphrase, Sigil assumes the key is unencrypted.

### Passphrase files

Passphrase files should contain only the passphrase, optionally followed by a trailing newline. UTF-8 BOM prefixes are automatically skipped. Trailing `\r\n` and `\n` are trimmed.

```
sigil sign artifact.bin --key key.pem --passphrase-file /run/secrets/passphrase
```

This is the recommended approach for CI/CD pipelines — mount the secret as a file and reference it with `--passphrase-file` or `SIGIL_PASSPHRASE_FILE`.

### Windows Credential Manager

On Windows, Sigil can store and retrieve passphrases from Windows Credential Manager (backed by DPAPI, protected by your Windows login credentials). This avoids environment variables, plaintext files, and repeated prompts.

#### Store a passphrase

```
sigil credential store --key mykey.pem
```

You'll be prompted to enter the passphrase. Sigil validates it by decrypting the key before storing. If the passphrase is wrong, nothing is stored.

```
Enter passphrase for key: ********
Passphrase stored for: C:\Users\you\keys\mykey.pem
```

Once stored, any signing command using `--key mykey.pem` will automatically retrieve the passphrase — no `--passphrase` or environment variable needed:

```
sigil sign artifact.bin --key mykey.pem
```

#### List stored passphrases

```
sigil credential list
```

Output shows key file paths only — passphrase values are never displayed:

```
C:\Users\you\keys\mykey.pem
C:\Users\you\keys\release-key.pem
```

#### Remove a stored passphrase

```
sigil credential remove --key mykey.pem
```

```
Passphrase removed for: C:\Users\you\keys\mykey.pem
```

After removal, signing with that key will require a passphrase from another source (CLI argument, file, environment variable, or interactive prompt).

#### How credential storage works

- Credentials are stored via the Windows `CredWrite` API with `CRED_TYPE_GENERIC`
- Encryption is handled by DPAPI — passphrases are protected by your Windows login credentials
- Target names use the format `sigil:passphrase:<absolute-key-path>`, so each key file has its own credential entry
- You can view stored credentials in Control Panel > Credential Manager > Windows Credentials (look for entries starting with `sigil:passphrase:`)
- Credential storage is available on Windows only. On other platforms, `sigil credential` commands report that credential storage is not supported

### Security recommendations

| Scenario | Recommended source |
|----------|-------------------|
| Interactive development (Windows) | Windows Credential Manager (`sigil credential store`) |
| Interactive development (Linux/macOS) | Interactive prompt (automatic) |
| CI/CD pipelines | `--passphrase-file` with a mounted secret |
| Automated scripts | `SIGIL_PASSPHRASE` or `SIGIL_PASSPHRASE_FILE` environment variable |
| Git commit signing | Windows Credential Manager or `SIGIL_PASSPHRASE` in shell profile |

Avoid `--passphrase` on the CLI when possible — the value may appear in shell history and process listings.

## CLI reference

```
sigil generate [-o prefix] [--passphrase "pass"] [--algorithm name]
sigil sign <file> [--key <private.pem|file.pfx>] [--vault <provider>] [--vault-key <reference>] [--keyless] [--oidc-token <jwt>] [--cert-store <thumbprint>] [--store-location <CurrentUser|LocalMachine>] [--output path] [--label "name"] [--passphrase "pass"] [--passphrase-file path] [--algorithm name] [--timestamp <tsa-url>] [--log-url <url>] [--log-api-key <key>]
sigil verify <file> [--signature path] [--trust-bundle path] [--authority fingerprint] [--discover uri] [--policy path]
sigil attest <file> --predicate <json> --type <type> [--key <private.pem|file.pfx>] [--vault <provider>] [--vault-key <reference>] [--cert-store <thumbprint>] [--store-location <CurrentUser|LocalMachine>] [--output path] [--passphrase "pass"] [--passphrase-file path] [--algorithm name] [--timestamp <tsa-url>]
sigil verify-attestation <file> [--attestation path] [--type type] [--trust-bundle path] [--authority fingerprint] [--discover uri] [--policy path]
sigil timestamp <envelope> --tsa <tsa-url> [--index <n>]
sigil trust create --name <name> [-o path] [--description "text"]
sigil trust add <bundle> --fingerprint <fp> [--name "display name"] [--not-after date] [--scope-names patterns...] [--scope-labels labels...] [--scope-algorithms algs...]
sigil trust remove <bundle> --fingerprint <fp>
sigil trust endorse <bundle> --endorser <fp> --endorsed <fp> [--statement "text"] [--not-after date] [--scope-names patterns...] [--scope-labels labels...]
sigil trust sign <bundle> --key <private.pem|file.pfx> | --vault <provider> --vault-key <reference> | --cert-store <thumbprint> [--store-location <CurrentUser|LocalMachine>] [-o path] [--passphrase "pass"] [--passphrase-file path]
sigil trust revoke <bundle> --fingerprint <fp> [--reason "text"]
sigil trust identity-add <bundle> --issuer <url> --subject <pattern> [--name "display name"] [--not-after date]
sigil trust identity-remove <bundle> --issuer <url> --subject <pattern>
sigil trust show <bundle>
sigil credential store --key <path>
sigil credential remove --key <path>
sigil credential list
sigil log append <envelope> [--log <path>] [--signature-index <n>]
sigil log verify [--log <path>] [--checkpoint <path>]
sigil log search [--log <path>] [--key <fp>] [--artifact <name>] [--digest <sha256>]
sigil log show [--log <path>] [--limit <n>] [--offset <n>]
sigil log proof [--log <path>] [--index <n>] [--old-size <m>]
sigil discover well-known <domain> [-o path]
sigil discover dns <domain> [-o path]
sigil discover git <url> [-o path]
sigil sign-image <image> [--key <private.pem|file.pfx>] [--vault <provider>] [--vault-key <reference>] [--cert-store <thumbprint>] [--store-location <CurrentUser|LocalMachine>] [--passphrase "pass"] [--passphrase-file path] [--algorithm name] [--label "name"] [--timestamp <tsa-url>] [--log-url <url>] [--log-api-key <key>]
sigil verify-image <image> [--trust-bundle path] [--authority fingerprint] [--discover uri] [--policy path]
sigil sign-manifest <path> [--key <private.pem|file.pfx>] [--vault <provider>] [--vault-key <reference>] [--cert-store <thumbprint>] [--store-location <CurrentUser|LocalMachine>] [--output path] [--label "name"] [--include "pattern"] [--passphrase "pass"] [--passphrase-file path] [--algorithm name] [--timestamp <tsa-url>] [--log-url <url>] [--log-api-key <key>]
sigil verify-manifest <manifest> [--base-path path] [--trust-bundle path] [--authority fingerprint] [--discover uri] [--policy path]
sigil sign-archive <archive> [--key <private.pem|file.pfx>] [--vault <provider>] [--vault-key <reference>] [--cert-store <thumbprint>] [--store-location <CurrentUser|LocalMachine>] [--output path] [--label "name"] [--passphrase "pass"] [--passphrase-file path] [--algorithm name] [--timestamp <tsa-url>] [--log-url <url>] [--log-api-key <key>]
sigil verify-archive <archive> [--signature path] [--trust-bundle path] [--authority fingerprint] [--discover uri] [--policy path]
sigil git config --key <private.pem|file.pfx> | --vault <provider> --vault-key <reference> | --cert-store <thumbprint> [--store-location <CurrentUser|LocalMachine>] [--global] [--passphrase "pass"] [--passphrase-file path]
sigil graph build --scan <path> [--output graph.json]
sigil graph query --graph <path> [--artifact <name>] [--key <fingerprint>] [--from <node-id>] [--to <node-id>] [--chain] [--signed-by] [--path] [--reach] [--revoked] [--impact]
sigil graph export --graph <path> --format <dot|json> [--output path]
```

**generate**: Create a key pair for persistent signing.
- `-o prefix` writes `prefix.pem` (private) and `prefix.pub.pem` (public)
- Without `-o`, prints private key PEM to stdout
- `--passphrase` encrypts the private key
- `--algorithm` selects the signing algorithm (default: `ecdsa-p256`)

**sign**: Sign a file. Five signing modes:
- Without `--key`, `--vault`, `--keyless`, or `--cert-store`: ephemeral mode (key generated in memory, discarded after signing)
- With `--key`: persistent mode (loads private key from PEM or PFX file, algorithm auto-detected). PFX files are auto-detected by `.pfx`/`.p12` extension
- With `--vault` and `--vault-key`: vault mode (private key never leaves the vault)
- With `--keyless`: keyless mode (ephemeral key + OIDC identity binding via GitHub Actions, GitLab CI, or `--oidc-token`)
- With `--cert-store`: Windows Certificate Store mode (key referenced by thumbprint, supports non-exportable/HSM-backed keys)
- `--key`, `--vault`, `--keyless`, and `--cert-store` are mutually exclusive
- `--store-location` selects `CurrentUser` (default) or `LocalMachine` store; requires `--cert-store`
- `--keyless` requires `--timestamp` (ephemeral keys need timestamps for trust evaluation)
- `--oidc-token` provides a manual OIDC JWT (requires `--keyless`); without it, the token is acquired from GitHub Actions or GitLab CI
- `--algorithm` only applies to ephemeral and keyless modes (default: `ecdsa-p256`)
- `--passphrase-file` reads the passphrase from a file (preferred over `--passphrase` for CI/CD)
- Passphrase resolution: `--passphrase` > `--passphrase-file` > `SIGIL_PASSPHRASE` > `SIGIL_PASSPHRASE_FILE` > Windows Credential Manager > interactive prompt. See [Passphrase and credential management](#passphrase-and-credential-management)
- `--timestamp` requests an RFC 3161 timestamp from the given TSA URL (non-fatal on failure)
- `--log-url` submits the signature to a remote transparency log after signing (non-fatal on failure). Use `rekor` for Sigstore Rekor, or `rekor:https://...` for a self-hosted Rekor instance
- `--log-api-key` provides the API key for Sigil LogServer write operations (not needed for Rekor)
- SBOM format is auto-detected for CycloneDX and SPDX JSON files

**attest**: Create a DSSE attestation for a file. Four signing modes (same as `sign`):
- Without `--key`, `--vault`, or `--cert-store`: ephemeral mode
- With `--key`: persistent mode (PEM or PFX, auto-detected)
- With `--vault` and `--vault-key`: vault mode
- With `--cert-store`: Windows Certificate Store mode
- `--predicate` and `--type` are required
- `--type` accepts short names (`slsa-provenance-v1`, `spdx-json`, `cyclonedx`) or any valid URI
- `--timestamp` requests an RFC 3161 timestamp (non-fatal on failure)
- If `--output` points to an existing `.att.json`, the new signature is appended

**verify-attestation**: Verify a DSSE attestation for a file.
- Public key is extracted from the `.att.json` — no key import needed
- Default attestation path is `<file>.att.json`; override with `--attestation`
- `--type` filters by predicate type — rejects attestations with a different type
- `--trust-bundle` and `--discover` enable trust evaluation (same as `verify`)
- `--policy` evaluates verification results against a declarative policy file (mutually exclusive with `--trust-bundle` and `--discover`)

**timestamp**: Apply RFC 3161 timestamp tokens to an existing signature envelope.
- `--tsa` is required — the URL of the Timestamp Authority
- `--index` timestamps a specific signature entry (0-based); without it, all un-timestamped entries are processed
- Already-timestamped entries are skipped

**verify**: Verify a file's signature.
- Public key is extracted from the `.sig.json` — no key import needed
- Algorithm is read from the envelope — works with any supported algorithm
- SBOM metadata is displayed when present in the envelope
- `--trust-bundle` and `--authority` enable trust evaluation on top of crypto verification
- `--discover` fetches a trust bundle via well-known URL, DNS, or git (mutually exclusive with `--trust-bundle`)
- `--policy` evaluates verification results against a declarative policy file (mutually exclusive with `--trust-bundle` and `--discover`)
- When using `--discover`, authority is auto-extracted from the bundle's signature if `--authority` is omitted

**trust create**: Create an empty unsigned trust bundle.

**trust add / remove**: Add or remove trusted keys from an unsigned bundle.

**trust endorse**: Add an endorsement ("Key A vouches for Key B") to an unsigned bundle.

**trust sign**: Sign a bundle with an authority key. `--key`, `--vault`/`--vault-key`, or `--cert-store` is required (mutually exclusive). This locks the bundle — modifications require re-signing.

**trust revoke**: Revoke a key in an unsigned bundle. The key remains in the key list but is marked as revoked. Revoked keys are rejected during trust evaluation. The bundle must be re-signed after adding revocations.

**trust identity-add**: Add a trusted OIDC identity to an unsigned bundle.
- `--issuer` is the OIDC issuer URL (exact match during verification)
- `--subject` is a glob pattern matching the JWT `sub` claim (e.g., `repo:myorg/*`)
- `--name` is an optional display name for the identity
- `--not-after` sets an expiry date for the identity trust entry

**trust identity-remove**: Remove a trusted OIDC identity from an unsigned bundle.
- Matches on both `--issuer` and `--subject` (both required)

**trust show**: Display the contents of a trust bundle (keys, endorsements, identities, revocations, signature status).

**credential store**: Store an encrypted key's passphrase in Windows Credential Manager.
- `--key` is required — the path to the private key file
- Prompts for the passphrase interactively (requires a terminal)
- Validates the passphrase by decrypting the key before storing
- Windows only — returns an error on other platforms

**credential remove**: Remove a stored passphrase from Windows Credential Manager.
- `--key` is required — the path to the private key file

**credential list**: List all key paths with stored passphrases.
- Shows key file paths only — passphrase values are never displayed
- Windows only — returns an error on other platforms

**log append**: Append a signing event to the transparency log.
- `<envelope>` is the path to a `.sig.json` file
- `--log` overrides the default log path (`.sigil.log.jsonl`)
- `--signature-index` selects which signature to log from a multi-signature envelope (default: 0)
- Duplicate signatures are rejected

**log verify**: Verify the integrity of the transparency log.
- Recomputes all leaf hashes and the Merkle root
- Checks the root matches the checkpoint file
- Reports invalid entries and checkpoint mismatches

**log search**: Search the log by key fingerprint, artifact name, or digest.
- At least one filter is required (`--key`, `--artifact`, or `--digest`)
- Filters can be combined (AND logic)

**log show**: Display all log entries.
- `--limit` and `--offset` for pagination

**log proof**: Generate and verify inclusion or consistency proofs.
- `--index` alone generates an inclusion proof (proves entry exists in the log)
- `--old-size` alone generates a consistency proof (proves the log is append-only)
- At least one of `--index` or `--old-size` is required

**discover well-known**: Fetch a trust bundle from `https://domain/.well-known/sigil/trust.json`.

**discover dns**: Look up `_sigil.domain` TXT records for a bundle URL, then fetch it.

**discover git**: Shallow-clone a git repository and read `.sigil/trust.json` or `trust.json`. Use `#branch` in the URL for a specific branch or tag.

**git config**: Configure git to use Sigil for commit/tag signing.
- `--key`, `--vault`/`--vault-key`, or `--cert-store` is required (mutually exclusive)
- `--key`: path to the private key PEM or PFX file (auto-detected by extension)
- `--vault` and `--vault-key`: vault provider and key reference (see [Vault-backed signing](#vault-backed-signing))
- `--cert-store`: Windows Certificate Store thumbprint (Windows only)
- `--store-location`: `CurrentUser` (default) or `LocalMachine`; requires `--cert-store`
- `--global` sets git config globally and enables `commit.gpgsign = true`
- Without `--global`, config is local (per-repository) and commits must be signed with `-S`
- Generates a wrapper script in `~/.sigil/` and sets `gpg.format`, `gpg.x509.program`, and `user.signingkey`
- Passphrases are NOT embedded in wrapper scripts. If the key is encrypted, the passphrase is resolved at signing time via the [resolution chain](#resolution-chain)
- On Windows with an encrypted key, a hint is shown to use `sigil credential store --key <path>` for seamless signing

**sign-image**: Sign an OCI container image in a registry.
- `<image>` is a full image reference (e.g., `ghcr.io/myorg/myapp:v1.0` or `registry/repo@sha256:...`)
- Four signing modes (same as `sign`): ephemeral, persistent (`--key`), vault (`--vault`/`--vault-key`), cert store (`--cert-store`)
- `--key`, `--vault`, and `--cert-store` are mutually exclusive
- `--algorithm` only applies to ephemeral mode (default: `ecdsa-p256`)
- `--timestamp` requests an RFC 3161 timestamp from the given TSA URL
- `--label` attaches a label to the signature
- `--log-url` submits the signature to a remote transparency log (non-fatal on failure)
- `--log-api-key` provides the API key for Sigil LogServer write operations
- Registry authentication is resolved automatically (see [Registry authentication](#registry-authentication))

**verify-image**: Verify signatures on an OCI container image.
- `<image>` is a full image reference
- Discovers Sigil signature artifacts via the OCI 1.1 referrers API
- `--trust-bundle` and `--authority` enable trust evaluation
- `--discover` fetches a trust bundle via well-known URL, DNS, or git (mutually exclusive with `--trust-bundle`)
- `--policy` evaluates verification results against a declarative policy file (mutually exclusive with `--trust-bundle` and `--discover`)

**sign-manifest**: Sign multiple files with a shared manifest signature.
- `<path>` is a directory (all files signed recursively)
- Four signing modes (same as `sign`): ephemeral, persistent (`--key`), vault (`--vault`/`--vault-key`), cert store (`--cert-store`)
- `--key`, `--vault`, and `--cert-store` are mutually exclusive
- `--include` filters files by glob pattern (e.g., `"*.dll"`)
- `--output` overrides default output path (`<path>/manifest.sig.json`)
- `--algorithm` only applies to ephemeral mode (default: `ecdsa-p256`)
- `--timestamp` requests an RFC 3161 timestamp from the given TSA URL
- `--label` attaches a label to the signature
- `--log-url` submits the signature to a remote transparency log (non-fatal on failure)
- `--log-api-key` provides the API key for Sigil LogServer write operations
- If `--output` points to an existing `.manifest.sig.json`, the new signature is appended
- SBOM format is auto-detected per file for CycloneDX and SPDX JSON files

**verify-manifest**: Verify a manifest signature covering multiple files.
- `<manifest>` is the path to a `.manifest.sig.json` file
- `--base-path` overrides the base directory for file resolution (default: manifest file's directory)
- Verifies per-file digest integrity and shared signature validity
- `--trust-bundle` and `--authority` enable trust evaluation
- `--discover` fetches a trust bundle via well-known URL, DNS, or git (mutually exclusive with `--trust-bundle`)
- `--policy` evaluates verification results against a declarative policy file (mutually exclusive with `--trust-bundle` and `--discover`)

**sign-archive**: Sign an archive file (ZIP, tar.gz, tar) with per-entry digests.
- `<archive>` is the path to a ZIP, tar.gz, or tar file (format auto-detected by magic bytes)
- Four signing modes (same as `sign`): ephemeral, persistent (`--key`), vault (`--vault`/`--vault-key`), cert store (`--cert-store`)
- `--key`, `--vault`, and `--cert-store` are mutually exclusive
- `--output` overrides default output path (`<archive>.archive.sig.json`)
- `--algorithm` only applies to ephemeral mode (default: `ecdsa-p256`)
- `--timestamp` requests an RFC 3161 timestamp from the given TSA URL
- `--label` attaches a label to the signature
- `--log-url` submits the signature to a remote transparency log (non-fatal on failure)
- `--log-api-key` provides the API key for Sigil LogServer write operations
- SBOM format is auto-detected per entry for CycloneDX and SPDX JSON entries
- NuGet `.nuspec` metadata is extracted from `.nupkg` archives (package id, version, authors)
- 500 MB per-entry size limit for zip bomb protection

**verify-archive**: Verify an archive signature with per-entry digest checking.
- `<archive>` is the path to the archive file
- Default signature path is `<archive>.archive.sig.json`; override with `--signature`
- Verifies per-entry digest integrity and shared signature validity
- Reports extra entries in the archive not covered by the envelope (warning, not failure)
- `--trust-bundle` and `--authority` enable trust evaluation
- `--discover` fetches a trust bundle via well-known URL, DNS, or git (mutually exclusive with `--trust-bundle`)
- `--policy` evaluates verification results against a declarative policy file (mutually exclusive with `--trust-bundle` and `--discover`)

**sign-pe**: Sign a PE binary (.exe, .dll) with an embedded Authenticode signature and a detached Sigil envelope.
- `<pe-file>` is the path to the PE binary
- Authenticode requires an X.509 certificate — PEM keys are rejected
- Two signing modes: PFX file (`--key`) or Windows Certificate Store (`--cert-store`)
- `--key` and `--cert-store` are mutually exclusive; one is required
- `--store-location` specifies `CurrentUser` (default) or `LocalMachine` (requires `--cert-store`)
- `--output` overrides the output path for the signed PE (default: overwrite in-place)
- `--envelope` overrides the output path for the `.sig.json` (default: `<pe-file>.sig.json`)
- `--label` attaches a label to the signature
- `--passphrase` / `--passphrase-file` provide the PFX decryption passphrase (resolved via passphrase chain)
- `--timestamp` requests an RFC 3161 timestamp from the given TSA URL (applied to both Authenticode and Sigil envelope)
- 500 MB file size limit

**verify-pe**: Verify the Authenticode signature and Sigil envelope of a PE binary.
- `<pe-file>` is the path to the PE binary
- Verifies the embedded Authenticode signature (digest recomputation + CMS signature check)
- Reports subject, issuer, thumbprint, digest algorithm, and timestamp if present
- If a `.sig.json` envelope exists, verifies it independently
- Default envelope path is `<pe-file>.sig.json`; override with `--signature`
- `--trust-bundle` and `--authority` enable trust evaluation on the Sigil envelope
- `--discover` fetches a trust bundle via well-known URL, DNS, or git (mutually exclusive with `--trust-bundle`)
- `--policy` evaluates verification results against a declarative policy file (mutually exclusive with `--trust-bundle` and `--discover`)
- 500 MB file size limit

**graph build**: Scan a directory and build a trust graph from all signing artifacts found.
- `--scan` is required — the directory to scan for `.sig.json`, `.manifest.sig.json`, `.archive.sig.json`, `.att.json`, and `trust.json` files
- `--output` writes the graph to a JSON file (default: `graph.json`)
- Deduplicates nodes by ID across files (first-write-wins for properties)

**graph query**: Query a trust graph.
- `--graph` is required — the path to a previously built graph JSON file
- `--artifact` + `--chain`: trace the signing chain from an artifact back to root authorities (follows SignedBy and EndorsedBy edges)
- `--key` + `--signed-by`: list all artifacts signed by a given key
- `--from` + `--to` + `--path`: find the shortest path between any two nodes
- `--key` + `--reach`: find all nodes reachable from a given key
- `--revoked` + `--impact`: find all artifacts transitively affected by revoked keys (traverses endorsement chains)

**graph export**: Export a trust graph for visualization or programmatic consumption.
- `--graph` is required — the path to a previously built graph JSON file
- `--format` is required — `dot` (Graphviz DOT) or `json`
- `--output` writes to a file; without it, writes to stdout
- DOT output uses shapes and colors: hexagons for keys, boxes for artifacts, ellipses for identities, diamonds for attestations, cylinders for log records; revoked edges are drawn in red

## Dotnet tool reference

Sigil is distributed as a [.NET tool](https://learn.microsoft.com/en-us/dotnet/core/tools/global-tools). The NuGet package is `Sigil.Sign`.

```
dotnet tool install --global Sigil.Sign
```

**Install globally** — available as `sigil` from any directory:

```
dotnet tool install --global Sigil.Sign
```

**Install as a local tool** — scoped to a repository, tracked in a manifest file:

```
dotnet new tool-manifest                    # creates .config/dotnet-tools.json (once per repo)
dotnet tool install Sigil.Sign              # adds sigil to the manifest
dotnet tool restore                         # restores tools on a fresh clone
dotnet sigil sign my-app.tar.gz             # run via 'dotnet sigil' instead of 'sigil'
```

**Update** to the latest version:

```
dotnet tool update --global Sigil.Sign      # global
dotnet tool update Sigil.Sign               # local
```

**Uninstall**:

```
dotnet tool uninstall --global Sigil.Sign   # global
dotnet tool uninstall Sigil.Sign            # local
```

**Check installed version**:

```
dotnet tool list --global                   # shows all global tools
dotnet tool list                            # shows local tools for current repo
```

| | Global | Local |
|---|---|---|
| Command | `sigil` | `dotnet sigil` |
| Scope | Machine-wide | Per-repository |
| Tracked in source | No | Yes (`.config/dotnet-tools.json`) |
| CI/CD restore | Not needed | `dotnet tool restore` |
| Multiple versions | No | Yes (different repos, different versions) |

### Usage examples (local tool)

When installed as a local tool, prefix all commands with `dotnet`. The arguments are identical to the CLI reference above.

**Sign and verify:**

```
dotnet sigil sign my-app.tar.gz
dotnet sigil verify my-app.tar.gz
```

**Generate keys and sign with a persistent key:**

```
dotnet sigil generate -o mykey
dotnet sigil sign my-app.tar.gz --key mykey.pem
```

**Sign with a vault key:**

```
dotnet sigil sign my-app.tar.gz --vault aws --vault-key alias/my-signing-key
```

**Trust bundles:**

```
dotnet sigil trust create --name "my-project" -o trust.json
dotnet sigil trust add trust.json --fingerprint sha256:abc123... --name "CI Key"
dotnet sigil trust sign trust.json --key authority.pem -o trust-signed.json
dotnet sigil verify release.tar.gz --trust-bundle trust-signed.json --authority sha256:def456...
```

**Attestations:**

```
dotnet sigil attest release.tar.gz --predicate provenance.json --type slsa-provenance-v1 --key mykey.pem
dotnet sigil verify-attestation release.tar.gz
dotnet sigil verify-attestation release.tar.gz --type slsa-provenance-v1 --trust-bundle trust-signed.json --authority sha256:def456...
```

**Policies:**

```
dotnet sigil verify release.tar.gz --policy policy.json
dotnet sigil verify-attestation release.tar.gz --policy policy.json
```

**Discovery:**

```
dotnet sigil discover well-known example.com -o trust.json
dotnet sigil verify release.tar.gz --discover example.com
```

**Container signing:**

```
dotnet sigil sign-image ghcr.io/myorg/myapp:v1.0 --key mykey.pem
dotnet sigil verify-image ghcr.io/myorg/myapp:v1.0
dotnet sigil verify-image ghcr.io/myorg/myapp:v1.0 --policy policy.json
```

**Manifest signing:**

```
dotnet sigil sign-manifest ./release/ --key mykey.pem
dotnet sigil sign-manifest ./release/ --include "*.dll" --key mykey.pem
dotnet sigil verify-manifest release/manifest.sig.json
dotnet sigil verify-manifest release/manifest.sig.json --policy policy.json
```

**Archive signing:**

```
dotnet sigil sign-archive release.zip --key mykey.pem
dotnet sigil sign-archive release.tar.gz --key mykey.pem --label "v2.1.0"
dotnet sigil verify-archive release.zip
dotnet sigil verify-archive release.zip --policy policy.json
```

**PE signing (Authenticode):**

```
dotnet sigil sign-pe app.exe --key codesigning.pfx --passphrase "changeit"
dotnet sigil sign-pe app.dll --cert-store ABC123DEF456
dotnet sigil verify-pe app.exe
dotnet sigil verify-pe app.exe --policy policy.json
```

**Git signing:**

```
dotnet sigil git config --key mykey.pem --global
```

**Trust graph:**

```
dotnet sigil graph build --scan ./release --output graph.json
dotnet sigil graph query --graph graph.json --artifact mylib.dll --chain
dotnet sigil graph query --graph graph.json --key sha256:a1b2c3... --signed-by
dotnet sigil graph query --graph graph.json --revoked --impact
dotnet sigil graph export --graph graph.json --format dot --output graph.dot
```

### CI/CD example

A typical GitHub Actions workflow using the local tool:

```yaml
- uses: actions/setup-dotnet@v4
  with:
    dotnet-version: '10.0.x'

- run: dotnet tool restore

- run: dotnet sigil sign my-app.tar.gz --key ${{ runner.temp }}/signing-key.pem --label "ci-pipeline"

- run: dotnet sigil attest my-app.tar.gz --predicate provenance.json --type slsa-provenance-v1 --key ${{ runner.temp }}/signing-key.pem

- run: dotnet sigil verify my-app.tar.gz --policy policy.json

- run: dotnet sigil verify-attestation my-app.tar.gz --type slsa-provenance-v1 --policy policy.json

- run: dotnet sigil sign-manifest ./publish/ --include "*.dll" --key ${{ runner.temp }}/signing-key.pem --label "ci-pipeline"

- run: dotnet sigil verify-manifest publish/manifest.sig.json --policy policy.json

- run: dotnet sigil sign-image ghcr.io/myorg/myapp:${{ github.sha }} --key ${{ runner.temp }}/signing-key.pem --label "ci-pipeline"

- run: dotnet sigil verify-image ghcr.io/myorg/myapp:${{ github.sha }} --policy policy.json
```

A typical GitLab CI pipeline using keyless signing:

```yaml
# .gitlab-ci.yml
sign:
  image: mcr.microsoft.com/dotnet/sdk:10.0
  id_tokens:
    SIGIL_ID_TOKEN:
      aud: sigil
  script:
    - dotnet tool restore
    - dotnet sigil sign artifact.tar.gz --keyless --timestamp https://freetsa.org/tsr
    - dotnet sigil verify artifact.tar.gz --trust-bundle trust.json
  artifacts:
    paths:
      - artifact.tar.gz.sig.json
```

## Trust graph engine

Sigil can ingest all your signing artifacts — signature envelopes, trust bundles, attestations, manifest/archive envelopes, and transparency log entries — into an in-memory directed graph. Query the graph to trace trust chains, list everything a key has signed, find the blast radius of a revoked key, or compute shortest paths between any two nodes. Export the graph in Graphviz DOT or JSON for visualization and further analysis.

**Key facts:**
- In-memory adjacency list — no database, no external dependencies
- Scans a directory for `.sig.json`, `.manifest.sig.json`, `.archive.sig.json`, `.att.json`, and `trust.json` files
- Five node types: Key, Artifact, Identity, Attestation, LogRecord
- Seven edge types: SignedBy, EndorsedBy, AttestedBy, RevokedAt, LoggedIn, IdentityBoundTo, ContainedIn
- Deduplication: nodes are merged by ID across files (first-write-wins for properties)
- Export to Graphviz DOT (with shapes and colors) or JSON

### Build a trust graph

Scan a directory containing signed artifacts and trust bundles:

```
sigil graph build --scan ./release --output graph.json
```

```
Ingested 5 file(s): 8 nodes, 12 edges.
Graph written to graph.json
```

The graph persists as `graph.json` and can be queried or exported in subsequent commands.

### Query the trust graph

**Trust chain** — trace the signing chain from an artifact back to root authorities:

```
sigil graph query --graph graph.json --artifact mylib.dll --chain
```

```
Trust chain for artifact:mylib.dll:
  artifact:mylib.dll
  key:sha256:a1b2c3...
  key:sha256:d4e5f6...
```

**Signed-by** — list everything a given key has signed:

```
sigil graph query --graph graph.json --key sha256:a1b2c3... --signed-by
```

```
Artifacts signed by key:sha256:a1b2c3...:
  artifact:mylib.dll
  artifact:myapp.exe
```

**Shortest path** — find the relationship path between any two nodes:

```
sigil graph query --graph graph.json --from "artifact:mylib.dll" --to "key:sha256:d4e5f6..." --path
```

```
Shortest path from artifact:mylib.dll to key:sha256:d4e5f6...:
  artifact:mylib.dll -> key:sha256:a1b2c3... -> key:sha256:d4e5f6...
```

**Reachability** — find all nodes reachable from a given node:

```
sigil graph query --graph graph.json --key sha256:a1b2c3... --reach
```

### Revoked key impact analysis

Find every artifact transitively affected by revoked keys — including artifacts signed by keys that were endorsed by the revoked key:

```
sigil graph query --graph graph.json --revoked --impact
```

```
Revoked key impact analysis:
  artifact:mylib.dll
  artifact:myapp.exe
```

This traverses endorsement chains: if key A endorsed key B and key A is revoked, all artifacts signed by key B are included in the impact.

### Export for visualization

**DOT format** — pipe to Graphviz for SVG/PNG rendering:

```
sigil graph export --graph graph.json --format dot --output graph.dot
dot -Tsvg graph.dot -o graph.svg
```

Node shapes indicate type: hexagons for keys, boxes for artifacts, ellipses for identities, diamonds for attestations, cylinders for log records. Revoked edges are drawn in red.

**JSON format** — structured export for programmatic consumption:

```
sigil graph export --graph graph.json --format json --output graph-export.json
```

Write to stdout (no `--output`) for piping:

```
sigil graph export --graph graph.json --format dot | dot -Tpng > graph.png
```

### How the trust graph works

The graph is built from existing Sigil data sources with no additional metadata:

| Source file | Nodes created | Edges created |
|---|---|---|
| `.sig.json` | Artifact + Key (+ Identity, LogRecord) | SignedBy (+ IdentityBoundTo, LoggedIn) |
| `trust.json` | Key + Identity | EndorsedBy, RevokedAt |
| `.manifest.sig.json` | Root Artifact + Subject Artifacts + Key | ContainedIn, SignedBy |
| `.att.json` | Artifact + Attestation + Key | AttestedBy, SignedBy |
| Log entries | LogRecord + Key + Artifact | LoggedIn, SignedBy |

Node IDs are deterministic: `key:<fingerprint>`, `artifact:<name>`, `identity:<issuer>/<pattern>`, `attestation:<type>:<name>`, `log:<index>`. The same node ID from different files is deduplicated automatically.

Query algorithms use BFS with visited-set cycle detection. Trust chain queries follow only SignedBy and EndorsedBy edges. Revoked impact analysis starts from keys with RevokedAt self-loop edges and transitively follows endorsement chains to find all affected downstream artifacts.

## What's coming

- **Key compromise impact analysis** — Instant blast radius assessment when a key leaks: all signed artifacts, affected releases, downstream dependencies, and remediation steps.
- **Time travel verification** — Replay trust decisions as-of a historical date for audits, legal compliance, and incident investigations (`sigil verify artifact.bin --at 2025-03-03`).
- **Environment fingerprint attestation** — Prove a build came from an approved golden image by capturing compiler hash, OS digest, and runner identity as a signed attestation.
- **Anomaly detection** — Behavioral baselines for signing patterns. Detect "validly signed, but not by the usual key for this project" without SaaS.
- **Plugin system** — Extension architecture for CVE scanners, license policy checks, SBOM diffing, and reproducibility validators.
- **Ed25519** — When the .NET SDK ships the native API.

## Install

Requires [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0).

Install as a global dotnet tool from NuGet:

```
dotnet tool install --global Sigil.Sign
```

Update to the latest version:

```
dotnet tool update --global Sigil.Sign
```

Or build from source:

```
git clone <repo-url>
cd <repo-name>
dotnet build Sigil.slnx
dotnet test Sigil.slnx
dotnet run --project src/Sigil.Cli -- sign somefile.txt
```

## License

[AGPL-3.0](LICENSE) — free to use, modify, and distribute. If you distribute a modified version, you must release your source under the same license.
