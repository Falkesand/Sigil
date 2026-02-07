# Sigil

Cryptographic signing and verification for any file. No cloud, no accounts, no dependencies.

## What it does

Sigil lets you **sign files** and **verify signatures**. That's it.

- Sign a file — Sigil produces a small `.sig.json` file next to it
- Anyone can verify the file hasn't been tampered with — the public key is embedded in the envelope
- No key store, no import/export, no hidden state

It works with any file: binaries, SBOMs, container images, config files, tarballs — anything.

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

Sigil supports multiple signing algorithms. The default is ECDSA P-256.

```
sigil generate -o mykey --algorithm ecdsa-p384
sigil generate -o mykey --algorithm rsa-pss-sha256
```

When signing with a PEM file, the algorithm is **auto-detected** — no need to specify it:

```
sigil sign my-app.tar.gz --key rsa-key.pem    # auto-detects RSA
sigil sign my-app.tar.gz --key ec-key.pem      # auto-detects P-256 or P-384
```

For ephemeral signing with a non-default algorithm:

```
sigil sign my-app.tar.gz --algorithm ecdsa-p384
```

## Ephemeral vs persistent

| | Ephemeral (default) | Persistent (`--key`) |
|---|---|---|
| Setup | None | `sigil generate -o keyname` |
| Identity proof | No (different key each time) | Yes (stable fingerprint) |
| Integrity proof | Yes | Yes |
| MITM protection | No (attacker can re-sign) | Yes (with trusted fingerprint) |
| Key management | None | User manages PEM file |
| CI/CD | Just works | Mount PEM file |
| Trust bundles (Phase 2) | Not useful | Yes |

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
    "name": "my-app.tar.gz"
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

This binds the signature to the file content, its metadata (name, digests), and all signature entry fields (algorithm, keyId, timestamp, label) — preventing substitution and replay attacks.

**Crypto.** All crypto comes from .NET's built-in `System.Security.Cryptography` — zero external dependencies.

| Algorithm | Name | Use case |
|-----------|------|----------|
| ECDSA P-256 | `ecdsa-p256` | Default. Fast, compact signatures, widely supported. |
| ECDSA P-384 | `ecdsa-p384` | CNSA suite compliance, enterprise/government requirements. |
| RSA-PSS | `rsa-pss-sha256` | Legacy interop, 3072-bit keys. |
| Ed25519 | `ed25519` | Planned — waiting for .NET SDK to ship the native API. |

PEM auto-detection means you never need to tell Sigil what algorithm a key uses — it parses the key's OID from the DER encoding and dispatches to the correct implementation.

## CLI reference

```
sigil generate [-o prefix] [--passphrase "pass"] [--algorithm name]
sigil sign <file> [--key <private.pem>] [--output path] [--label "name"] [--passphrase "pass"] [--algorithm name]
sigil verify <file> [--signature path]
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

**verify**: Verify a file's signature.
- Public key is extracted from the `.sig.json` — no key import needed
- Algorithm is read from the envelope — works with any supported algorithm

## What's coming

- **Trust bundles** — Curated, signed lists of trusted keys. Like browser CA stores, but anyone can create one.
- **Endorsements** — Lightweight "Key A vouches for Key B" statements.
- **Ed25519** — When the .NET native API ships.
- **ML-DSA-65** — Post-quantum signatures.
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
dotnet build
dotnet run --project src/Sigil.Cli -- sign somefile.txt
```

## License

MIT
