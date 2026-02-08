# Sigil

Cryptographic signing and verification for any file. No cloud, no accounts, no dependencies beyond the .NET BCL.

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
| Needs internet | No | Yes | No | Depends |
| Stores your email | No | Yes (public log) | Optional | Yes |
| External dependencies | Zero | Many | Many | Many |
| Key management | None (ephemeral) or PEM files | Ephemeral | Complex | Complex |
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

## Ephemeral vs persistent

| | Ephemeral (default) | Persistent (`--key`) |
|---|---|---|
| Setup | None | `sigil generate -o keyname` |
| Identity proof | No (different key each time) | Yes (stable fingerprint) |
| Integrity proof | Yes | Yes |
| MITM protection | No (attacker can re-sign) | Yes (with trusted fingerprint) |
| Key management | None | User manages PEM file |
| CI/CD | Just works | Mount PEM file |
| Trust bundles | Not useful | Yes |

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
      "label": "ci-pipeline"
    }
  ]
}
```

The `publicKey` field contains the base64-encoded SPKI public key. During verification, Sigil computes the fingerprint of this key and checks it matches `keyId` — preventing public key substitution.

The `mediaType` and `metadata` fields are only present for detected SBOM files. They are `null`/absent for regular files.

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

## CLI reference

```
sigil generate [-o prefix] [--passphrase "pass"] [--algorithm name]
sigil sign <file> [--key <private.pem>] [--output path] [--label "name"] [--passphrase "pass"] [--algorithm name]
sigil verify <file> [--signature path] [--trust-bundle path] [--authority fingerprint]
sigil trust create --name <name> [-o path] [--description "text"]
sigil trust add <bundle> --fingerprint <fp> [--name "display name"] [--not-after date] [--scope-names patterns...] [--scope-labels labels...] [--scope-algorithms algs...]
sigil trust remove <bundle> --fingerprint <fp>
sigil trust endorse <bundle> --endorser <fp> --endorsed <fp> [--statement "text"] [--not-after date] [--scope-names patterns...] [--scope-labels labels...]
sigil trust sign <bundle> --key <private.pem> [-o path] [--passphrase "pass"]
sigil trust show <bundle>
```

**generate**: Create a key pair for persistent signing.
- `-o prefix` writes `prefix.pem` (private) and `prefix.pub.pem` (public)
- Without `-o`, prints private key PEM to stdout
- `--passphrase` encrypts the private key
- `--algorithm` selects the signing algorithm (default: `ecdsa-p256`)

**sign**: Sign a file.
- Without `--key`: ephemeral mode (key generated in memory, discarded after signing)
- With `--key`: persistent mode (loads private key from PEM file, algorithm auto-detected)
- `--algorithm` only applies to ephemeral mode (default: `ecdsa-p256`)
- SBOM format is auto-detected for CycloneDX and SPDX JSON files

**verify**: Verify a file's signature.
- Public key is extracted from the `.sig.json` — no key import needed
- Algorithm is read from the envelope — works with any supported algorithm
- SBOM metadata is displayed when present in the envelope
- `--trust-bundle` and `--authority` enable trust evaluation on top of crypto verification

**trust create**: Create an empty unsigned trust bundle.

**trust add / remove**: Add or remove trusted keys from an unsigned bundle.

**trust endorse**: Add an endorsement ("Key A vouches for Key B") to an unsigned bundle.

**trust sign**: Sign a bundle with an authority key. This locks the bundle — modifications require re-signing.

**trust show**: Display the contents of a trust bundle (keys, endorsements, signature status).

## What's coming

- **Ed25519** — When the .NET SDK ships the native API.
- **Discovery** — Optional well-known URLs, DNS records, and git-based trust bundles.

## Install

Requires [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0).

```
dotnet tool install --global Sigil.Cli
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

MIT
