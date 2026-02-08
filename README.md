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
  - [Sign with a vault key](#sign-with-a-vault-key)
  - [Sign with a hardware token](#sign-with-a-hardware-token)
  - [Add a timestamp](#add-a-timestamp)
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
- [Discovery](#discovery)
  - [Well-known URLs](#well-known-urls)
  - [DNS TXT records](#dns-txt-records)
  - [Git repositories](#git-repositories)
  - [Verify with discovery](#verify-with-discovery)
- [CLI reference](#cli-reference)
- [Dotnet tool reference](#dotnet-tool-reference)
- [What's coming](#whats-coming)
- [Install](#install)
- [License](#license)

## What it does

Sigil lets you **sign files** and **verify signatures**. That's it.

- Sign a file — Sigil produces a small `.sig.json` file next to it
- Anyone can verify the file hasn't been tampered with — the public key is embedded in the envelope
- No key store, no import/export, no hidden state

It works with any file: binaries, SBOMs, container images, config files, tarballs — anything. When signing a CycloneDX or SPDX JSON file, Sigil automatically detects the format and embeds SBOM metadata in the signature envelope.

## Why not just use Sigstore/PGP/X.509?

| | Sigil | Sigstore | PGP | X.509 |
|---|---|---|---|---|
| Needs an account | No | Yes (OIDC) | No | Yes (CA) |
| Trusted timestamping | Yes (RFC 3161) | Yes (Rekor) | No | Yes (RFC 3161) |
| Needs internet | No | Yes | No | Depends |
| Stores your email | No | Yes (public log) | Optional | Yes |
| External dependencies | Zero | Many | Many | Many |
| Key management | None (ephemeral), PEM files, vault/KMS, or PKCS#11 | Ephemeral | Complex | Complex |
| Vault/KMS support | Yes (4 cloud + PKCS#11) | PKCS#11 | No | Partial |
| Works offline | Yes | No | Yes | Partial |
| Hidden state on disk | None | None | `~/.gnupg/` | Varies |
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
sigil generate -o mykey --algorithm rsa-pss-sha256
sigil generate -o mykey --algorithm ml-dsa-65
```

When signing with a PEM file, the algorithm is **auto-detected** — no need to specify it:

```
sigil sign my-app.tar.gz --key rsa-key.pem    # auto-detects RSA
sigil sign my-app.tar.gz --key ec-key.pem      # auto-detects P-256 or P-384
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
Components: 3
  [VERIFIED] sha256:c017446b9040d...

All signatures VERIFIED.
```

The metadata is embedded in the signed subject, so it is tamper-proof. Non-SBOM files are signed without metadata — no behavior changes for regular files.

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

## Ephemeral vs persistent vs vault

| | Ephemeral (default) | Persistent (`--key`) | Vault (`--vault`) |
|---|---|---|---|
| Setup | None | `sigil generate -o keyname` | Configure vault + auth |
| Identity proof | No (different key each time) | Yes (stable fingerprint) | Yes (stable fingerprint) |
| Integrity proof | Yes | Yes | Yes |
| MITM protection | No (attacker can re-sign) | Yes (with trusted fingerprint) | Yes (with trusted fingerprint) |
| Key management | None | User manages PEM file | Vault manages key |
| Private key exposure | In memory (discarded) | On disk (PEM file) | Never leaves vault |
| CI/CD | Just works | Mount PEM file | IAM roles / service accounts |
| Trust bundles | Not useful | Yes | Yes |

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
      "timestampToken": "base64-DER..."
    }
  ]
}
```

The `publicKey` field contains the base64-encoded SPKI public key. During verification, Sigil computes the fingerprint of this key and checks it matches `keyId` — preventing public key substitution.

The `mediaType` and `metadata` fields are only present for detected SBOM files. They are `null`/absent for regular files.

The `timestampToken` field is present only when an RFC 3161 timestamp has been applied. It contains the base64-encoded DER of a CMS/PKCS#7 signed timestamp token from a Timestamp Authority. See [Timestamping](#timestamping).

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
| RSA-PSS | `rsa-pss-sha256` | Legacy interop, 3072-bit keys. |
| ML-DSA-65 | `ml-dsa-65` | Post-quantum (FIPS 204). Requires platform support. |
| Ed25519 | `ed25519` | Planned — waiting for .NET SDK to ship the native API. |

PEM auto-detection means you never need to tell Sigil what algorithm a key uses — it parses the key's OID from the DER encoding and dispatches to the correct implementation.

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

This says: trust this key only for signing `.tar.gz` and `.zip` files, only when labeled `ci-pipeline`, only with ECDSA P-256, and only until January 2027. If any of those conditions aren't met, you'll see `[SCOPE_MISMATCH]` or `[EXPIRED]` instead of `[TRUSTED]`.

### Endorsements

Sometimes you want to say "I trust Key A, and Key A vouches for Key B." Endorsements let you do this without adding Key B directly to the bundle.

```
sigil trust endorse trust.json \
  --endorser sha256:aaa... \
  --endorsed sha256:bbb... \
  --statement "Authorized build key for CI"
```

When Sigil evaluates trust, if it finds a matching endorsement from a key that's directly in the bundle, the endorsed key is treated as trusted:

```
  [TRUSTED] sha256:bbb...
           Endorsed by CI Pipeline Key.
```

Endorsements are **non-transitive**: if Key A endorses Key B, and Key B endorses Key C, Key C is **not** trusted. Only the bundle authority decides which endorsements to include, and only direct bundle keys can be endorsers.

Endorsements can also have scopes and expiry dates, further restricting what the endorsed key is trusted for.

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

Signature: PRESENT
  Signed by: sha256:def456...
  Algorithm: ecdsa-p256
  Timestamp: 2026-02-08T12:00:00Z
```

### How trust evaluation works

When you pass `--trust-bundle` and `--authority` to `sigil verify`, here's what happens for each signature:

1. **Verify the bundle** — Check that the bundle is signed by the authority you specified. If not, the bundle is rejected entirely.
2. **Check the crypto** — If the cryptographic signature is invalid, the key is `Untrusted` regardless of what the bundle says. Crypto trumps trust.
3. **Look up the key** — Search for the signing key's fingerprint in the bundle's key list.
4. **If found** — Check expiry, then check scopes. If everything passes: `Trusted`.
5. **If not found** — Search endorsements where this key is endorsed by a key that *is* in the bundle (and that endorser isn't expired, and the endorsement isn't expired, and the scopes match). If found: `TrustedViaEndorsement`. Otherwise: `Untrusted`.

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

**Example:**

```
sigil sign release.tar.gz --vault gcp \
  --vault-key projects/my-project/locations/us/keyRings/my-ring/cryptoKeys/my-key/cryptoKeyVersions/1
```

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
| SoftHSM2 (testing) | `/usr/lib/softhsm/libsofthsm2.so` |
| YubiKey (macOS) | `/usr/local/lib/libykcs11.dylib` |
| YubiKey (Linux) | `/usr/lib/libykcs11.so` |
| OpenSC (smart cards) | `/usr/lib/opensc-pkcs11.so` |
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
| RSA | `rsa-pss-sha256` |

**Security notes:**

- Avoid putting PINs in URIs for production use — prefer `PKCS11_PIN` or `--passphrase`
- PINs in URIs may appear in shell history, process listings, and log files
- The `--passphrase` option is reused for PKCS#11 PINs when using `--vault pkcs11`

## CLI reference

```
sigil generate [-o prefix] [--passphrase "pass"] [--algorithm name]
sigil sign <file> [--key <private.pem>] [--vault <provider>] [--vault-key <reference>] [--output path] [--label "name"] [--passphrase "pass"] [--algorithm name] [--timestamp <tsa-url>]
sigil verify <file> [--signature path] [--trust-bundle path] [--authority fingerprint] [--discover uri]
sigil timestamp <envelope> --tsa <tsa-url> [--index <n>]
sigil trust create --name <name> [-o path] [--description "text"]
sigil trust add <bundle> --fingerprint <fp> [--name "display name"] [--not-after date] [--scope-names patterns...] [--scope-labels labels...] [--scope-algorithms algs...]
sigil trust remove <bundle> --fingerprint <fp>
sigil trust endorse <bundle> --endorser <fp> --endorsed <fp> [--statement "text"] [--not-after date] [--scope-names patterns...] [--scope-labels labels...]
sigil trust sign <bundle> --key <private.pem> | --vault <provider> --vault-key <reference> [-o path] [--passphrase "pass"]
sigil trust show <bundle>
sigil discover well-known <domain> [-o path]
sigil discover dns <domain> [-o path]
sigil discover git <url> [-o path]
```

**generate**: Create a key pair for persistent signing.
- `-o prefix` writes `prefix.pem` (private) and `prefix.pub.pem` (public)
- Without `-o`, prints private key PEM to stdout
- `--passphrase` encrypts the private key
- `--algorithm` selects the signing algorithm (default: `ecdsa-p256`)

**sign**: Sign a file. Three signing modes:
- Without `--key` or `--vault`: ephemeral mode (key generated in memory, discarded after signing)
- With `--key`: persistent mode (loads private key from PEM file, algorithm auto-detected)
- With `--vault` and `--vault-key`: vault mode (private key never leaves the vault)
- `--vault` and `--key` are mutually exclusive
- `--algorithm` only applies to ephemeral mode (default: `ecdsa-p256`)
- `--timestamp` requests an RFC 3161 timestamp from the given TSA URL (non-fatal on failure)
- SBOM format is auto-detected for CycloneDX and SPDX JSON files

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
- When using `--discover`, authority is auto-extracted from the bundle's signature if `--authority` is omitted

**trust create**: Create an empty unsigned trust bundle.

**trust add / remove**: Add or remove trusted keys from an unsigned bundle.

**trust endorse**: Add an endorsement ("Key A vouches for Key B") to an unsigned bundle.

**trust sign**: Sign a bundle with an authority key. Either `--key` or `--vault`/`--vault-key` is required (mutually exclusive). This locks the bundle — modifications require re-signing.

**trust show**: Display the contents of a trust bundle (keys, endorsements, signature status).

**discover well-known**: Fetch a trust bundle from `https://domain/.well-known/sigil/trust.json`.

**discover dns**: Look up `_sigil.domain` TXT records for a bundle URL, then fetch it.

**discover git**: Shallow-clone a git repository and read `.sigil/trust.json` or `trust.json`. Use `#branch` in the URL for a specific branch or tag.

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

**Discovery:**

```
dotnet sigil discover well-known example.com -o trust.json
dotnet sigil verify release.tar.gz --discover example.com
```

### CI/CD example

A typical GitHub Actions workflow using the local tool:

```yaml
- uses: actions/setup-dotnet@v4
  with:
    dotnet-version: '10.0.x'

- run: dotnet tool restore

- run: dotnet sigil sign my-app.tar.gz --key ${{ runner.temp }}/signing-key.pem --label "ci-pipeline"

- run: dotnet sigil verify my-app.tar.gz
```

## What's coming

- **Attestations (SLSA/in-toto)** — Signed build provenance statements following the in-toto attestation format.
- **Policy engine** — Declarative verification rules (min signatures, required timestamps, algorithm restrictions).
- **Transparency log** — Append-only Merkle tree log for auditable signing events.
- **Git commit signing** — Drop-in replacement for GPG via `gpg.program` / `gpg.format`.
- **Container/OCI signing** — Sign container images in OCI registries using the referrers API.
- **Signature revocation** — Revoke individual signatures or keys without re-signing the trust bundle.
- **Batch/manifest signing** — Sign multiple files in one operation with a single envelope.
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
