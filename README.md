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

Multiple parties can independently sign the same file. A build system signs it, then an auditor signs it — both signatures live in the same envelope:

```
sigil sign release.tar.gz --key build-key.pem --label "ci-pipeline"
# Later, someone else:
sigil sign release.tar.gz --key audit-key.pem --label "security-review"
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
JCS-canonicalized(subject metadata) + SHA-256(file bytes)
```

This binds the signature to both the file content and its metadata (name, digests), preventing substitution attacks.

**Crypto.** ECDSA with NIST P-256 curve. All crypto comes from .NET's built-in `System.Security.Cryptography` — zero external dependencies. Ed25519 support will be added when .NET ships the native API.

## CLI reference

```
sigil generate [-o prefix] [--passphrase "pass"]
sigil sign <file> [--key <private.pem>] [--output path] [--label "name"] [--passphrase "pass"]
sigil verify <file> [--signature path]
```

**generate**: Create a key pair for persistent signing.
- `-o prefix` writes `prefix.pem` (private) and `prefix.pub.pem` (public)
- Without `-o`, prints private key PEM to stdout
- `--passphrase` encrypts the private key

**sign**: Sign a file.
- Without `--key`: ephemeral mode (key generated in memory, discarded after signing)
- With `--key`: persistent mode (loads private key from PEM file)

**verify**: Verify a file's signature.
- Public key is extracted from the `.sig.json` — no key import needed

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
cd secure
dotnet build
dotnet run --project src/Sigil.Cli -- sign somefile.txt
```

## License

MIT
