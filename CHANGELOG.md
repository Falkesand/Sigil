# Changelog

## 0.9.0

### Added

- Ed25519 and Ed448 signing support via BouncyCastle cryptographic provider
- `CryptoProviderRegistry` extensibility pattern for pluggable algorithm implementations
- `Sigil.Crypto.BouncyCastle` package with `BouncyCastleCryptoProvider.Register()` entry point

### Fixed

- Predicate type URI domain corrected to canonical `sigil.dev` domain

## 0.6.0

### Fixed

- **HashiCorp Vault Transit: public key extraction** — VaultSharp returns `JsonElement` objects at runtime for Transit key version data. The previous code called `.ToString()` which returned the full JSON object instead of the PEM public key string, causing `ImportFromPem` to fail. Added `ExtractPublicKeyPem()` to properly handle `JsonElement` deserialization.
- **HashiCorp Vault Transit: ECDSA signature format** — Vault Transit with ASN.1 marshaling returned DER-encoded signatures, but .NET's `ECDsa.VerifyData()` defaults to IEEE P1363 format. Changed to JWS marshaling (P1363) with proper base64url decoding to match .NET's expected format.
- **HashiCorp Vault Transit: RSA-PSS salt length** — Vault defaults to maximum salt length (222 bytes for RSA-2048), but .NET's `RSASignaturePadding.Pss` uses salt equal to hash length (32 bytes for SHA-256). Set `SaltLength = "hash"` on Vault sign requests for cross-platform compatibility.
- **Multiple signatures overwritten instead of appended** — When signing the same artifact twice with `--output` pointing to an existing envelope, the second signature replaced the first instead of appending. The sign command now loads the existing envelope and appends the new signature.
- **Bare catch in ConvertPemToSpki** — Narrowed from `catch` to `catch (CryptographicException)` to avoid swallowing unrelated exceptions.

## 0.5.0

### Added

- Vault-backed signing with four providers: HashiCorp Vault, Azure Key Vault, AWS KMS, Google Cloud KMS
- `--vault` and `--vault-key` options on `sign` and `trust sign` commands
- Async signing support (`ISigner.SignAsync`) for vault providers
- 30-second timeout on all vault API calls
- Trust bundle signing via vault (`sigil trust sign --vault`)

## 0.4.0

### Added

- Trust bundle discovery: well-known URLs, DNS TXT records, git repositories
- `sigil discover well-known`, `sigil discover dns`, `sigil discover git` commands
- `--discover` option on `sigil verify` for automatic trust bundle fetching
- Raw UDP DNS TXT query client (BCL-only, zero external dependencies)
- Git bundle resolver with shallow clone and branch support
- Discovery dispatcher with scheme-based routing

## 0.3.0

### Added

- ML-DSA-65 post-quantum signatures (FIPS 204) with runtime support detection
- SBOM auto-detection for CycloneDX and SPDX JSON files
- SBOM metadata embedded in signed subject (tamper-proof)
- `SbomDetector`, `CycloneDxParser`, `SpdxParser` in `Sigil.Sbom` namespace

## 0.2.0

### Added

- Trust bundles: signed JSON with trusted keys, scopes, endorsements
- `sigil trust create`, `trust add`, `trust remove`, `trust endorse`, `trust sign`, `trust show` commands
- `--trust-bundle` and `--authority` options on `sigil verify`
- Scope matching with glob patterns for names, labels, algorithms
- Non-transitive endorsements
- Bundle signature verification with JCS canonicalization

## 0.1.0

### Added

- Multi-algorithm support: ECDSA P-256, ECDSA P-384, RSA-PSS, with Ed25519 stub
- Embedded public keys in signature envelopes (self-contained verification)
- `SignerFactory` and `VerifierFactory` with automatic algorithm detection from PEM/SPKI
- `AlgorithmDetector` parsing SPKI/PKCS8 DER OIDs
- Key generation, signing, and verification CLI commands
- Ephemeral signing mode (zero setup)
- JCS (RFC 8785) canonicalization for deterministic signing payloads
