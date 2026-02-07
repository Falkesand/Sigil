# Sigil

Cryptographic signing and verification for any file. No cloud, no accounts, no dependencies.

## What it does

Sigil lets you **sign files** and **verify signatures**. That's it.

- You generate a key pair
- You sign a file — Sigil produces a small `.sig.json` file next to it
- Anyone with your public key can verify the file hasn't been tampered with

It works with any file: binaries, SBOMs, container images, config files, tarballs — anything.

## Why not just use Sigstore/PGP/X.509?

| | Sigil | Sigstore | PGP | X.509 |
|---|---|---|---|---|
| Needs an account | No | Yes (OIDC) | No | Yes (CA) |
| Needs internet | No | Yes | No | Depends |
| Stores your email | No | Yes (public log) | Optional | Yes |
| External dependencies | Zero | Many | Many | Many |
| Key management | Simple files | Ephemeral | Complex | Complex |
| Works offline | Yes | No | Yes | Partial |

Sigil is for people who want to sign things **without asking permission from a cloud service**.

## Quick start

### Generate a key

```
sigil keys generate --label "my-key"
```

Output:
```
Key generated: sha256:9c8b0e1d9d9cd9e2...
Label: my-key
```

Your keys live in `~/.sigil/keys/`. The private key stays on your machine.

### Sign a file

```
sigil sign my-app.tar.gz --key 9c8b0e
```

This creates `my-app.tar.gz.sig.json` — a detached signature envelope:

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
      "value": "base64...",
      "timestamp": "2026-02-07T14:30:00Z"
    }
  ]
}
```

### Verify a file

```
sigil verify my-app.tar.gz
```

Output:
```
Artifact: my-app.tar.gz
Digests: MATCH
  [VERIFIED] sha256:9c8b0e1d... (my-key)

All signatures VERIFIED.
```

If someone tampers with the file:

```
FAILED: Artifact digest mismatch — file has been modified.
```

### Share your public key

```
sigil keys export 9c8b0e > my-key.pub.pem
```

Someone else imports it:

```
sigil keys import my-key.pub.pem --label "alice"
```

Now they can verify files you signed.

## Multiple signatures

Multiple parties can independently sign the same file. A build system signs it, then an auditor signs it — both signatures live in the same envelope:

```
sigil sign release.tar.gz --key build-key --label "ci-pipeline"
# Later, someone else:
sigil sign release.tar.gz --key audit-key --label "security-review"
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

**Signatures are detached.** Sigil never modifies your files. It produces a separate `.sig.json` envelope containing the file's digests and cryptographic signatures.

**Signing payload.** What actually gets signed is:

```
JCS-canonicalized(subject metadata) + SHA-256(file bytes)
```

This binds the signature to both the file content and its metadata (name, digests), preventing substitution attacks.

**Crypto.** ECDSA with NIST P-256 curve. All crypto comes from .NET's built-in `System.Security.Cryptography` — zero external dependencies. Ed25519 support will be added when .NET ships the native API.

## Key management

Keys are stored as standard PEM files:

```
~/.sigil/
  keys/
    sha256_<fingerprint>/
      public.pem       # Standard SubjectPublicKeyInfo
      private.pem      # PKCS#8 (encrypted if passphrase set)
      metadata.json    # Algorithm, label, creation date
```

Encrypt your private key with a passphrase:

```
sigil keys generate --label "production" --passphrase
```

## CLI reference

```
sigil keys generate [--label "name"] [--passphrase "pass"]
sigil keys list
sigil keys export <fingerprint>
sigil keys import <file> [--label "name"]

sigil sign <file> --key <fingerprint> [--output path] [--label "name"]
sigil verify <file> [--signature path]
```

Fingerprints support prefix matching — you only need enough characters to be unambiguous (e.g., `9c8b0e` instead of the full 71-character fingerprint).

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
dotnet run --project src/Sigil.Cli -- keys generate
```

## License

MIT
