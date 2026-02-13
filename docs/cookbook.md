# Sigil Cookbook

Practical recipes for every Sigil capability. Copy-paste ready.

> **Note:** This cookbook was written in February 2026. Commands and options may evolve. Run `sigil --help` or `sigil <command> --help` for the most current syntax.

---

## Table of Contents

1. [Getting Started](#1-getting-started)
2. [Key Generation](#2-key-generation)
3. [Signing Files](#3-signing-files)
4. [Verifying Signatures](#4-verifying-signatures)
5. [Multiple Signatures](#5-multiple-signatures)
6. [Trust Bundles](#6-trust-bundles)
7. [Key Endorsements](#7-key-endorsements)
8. [Key Revocation](#8-key-revocation)
9. [Key Scoping](#9-key-scoping)
10. [OIDC Identities in Trust Bundles](#10-oidc-identities-in-trust-bundles)
11. [Trust Bundle Signing](#11-trust-bundle-signing)
12. [Discovery](#12-discovery)
13. [SBOM Signing](#13-sbom-signing)
14. [Manifest Signing (Multi-File)](#14-manifest-signing-multi-file)
15. [Archive Signing](#15-archive-signing)
16. [Container/OCI Image Signing](#16-containeroci-image-signing)
17. [PE Binary Signing (Authenticode)](#17-pe-binary-signing-authenticode)
18. [Git Commit Signing](#18-git-commit-signing)
19. [Attestations](#19-attestations)
20. [Environment Fingerprint Attestation](#20-environment-fingerprint-attestation)
21. [Policy Enforcement](#21-policy-enforcement)
22. [RFC 3161 Timestamping](#22-rfc-3161-timestamping)
23. [Transparency Logs](#23-transparency-logs)
24. [Remote Transparency Logs](#24-remote-transparency-logs)
25. [Keyless/OIDC Signing](#25-keylessoidc-signing)
26. [Vault-Backed Signing](#26-vault-backed-signing)
27. [Hardware Tokens (PKCS#11)](#27-hardware-tokens-pkcs11)
28. [Windows Certificate Store](#28-windows-certificate-store)
29. [PFX/PKCS#12 Certificates](#29-pfxpkcs12-certificates)
30. [Passphrase Management](#30-passphrase-management)
31. [Trust Graph](#31-trust-graph)
32. [Key Compromise Impact Analysis](#32-key-compromise-impact-analysis)
33. [Time Travel Verification](#33-time-travel-verification)
34. [Anomaly Detection](#34-anomaly-detection)
35. [CI/CD Recipes](#35-cicd-recipes)
36. [Enterprise Scenarios](#36-enterprise-scenarios)
37. [Secure Passphrase Handling](#37-secure-passphrase-handling)
38. [Environment Variables Reference](#38-environment-variables-reference)
39. [Vault Authentication Patterns](#39-vault-authentication-patterns)
40. [Hardware Token Security (PKCS#11)](#40-hardware-token-security-pkcs11)
41. [OCI Registry Authentication](#41-oci-registry-authentication)
42. [Log Server Authentication](#42-log-server-authentication)
43. [Security Best Practices Summary](#43-security-best-practices-summary)

---

## 1. Getting Started

### Install from pre-built binary (recommended)

Download the latest release for your platform from [GitHub Releases](https://github.com/Falkesand/Sigil/releases). No .NET SDK or runtime required.

**Bash/Linux/macOS:**
```bash
# Extract and add to PATH
tar -xzf sigil-linux-x64.tar.gz
sudo mv sigil /usr/local/bin/
```

**PowerShell/Windows:**
```powershell
# Extract and add to PATH (or just run from the extracted directory)
Expand-Archive sigil-win-x64.zip -DestinationPath C:\Tools\Sigil
# Add to PATH (current session)
$env:PATH += ";C:\Tools\Sigil"
# Add to PATH (permanent, current user)
[Environment]::SetEnvironmentVariable("PATH", $env:PATH + ";C:\Tools\Sigil", "User")
```

### Install as .NET global tool

```bash
dotnet tool install -g Sigil.Sign
```

### Your first signature (zero setup)

```bash
# Sign any file — creates an ephemeral key, produces myfile.tar.gz.sig.json
sigil sign myfile.tar.gz

# Verify it — public key is embedded in the signature envelope
sigil verify myfile.tar.gz
```

---

## 2. Key Generation

### Generate a default key pair (ECDSA P-256)

```bash
sigil generate -o mykey
# Creates: mykey.pem (private) and mykey.pub.pem (public)
```

### Generate with a specific algorithm

```bash
# ECDSA curves
sigil generate -o key-p256 --algorithm ecdsa-p256
sigil generate -o key-p384 --algorithm ecdsa-p384
sigil generate -o key-p521 --algorithm ecdsa-p521

# RSA
sigil generate -o key-rsa --algorithm rsa-pss-sha256

# Post-quantum
sigil generate -o key-mldsa --algorithm ml-dsa-65

# Edwards curves (via BouncyCastle provider)
sigil generate -o key-ed25519 --algorithm ed25519
sigil generate -o key-ed448 --algorithm ed448
```

### Generate with an encrypted private key

```bash
# Interactive passphrase prompt
sigil generate -o mykey --passphrase "my-secret-passphrase"

# From a file
sigil generate -o mykey --passphrase-file /secrets/key-passphrase.txt
```

---

## 3. Signing Files

### Sign with an ephemeral key (disposable, no identity)

```bash
sigil sign release.tar.gz
# Output: release.tar.gz.sig.json
```

### Sign with a persistent key

```bash
sigil sign release.tar.gz --key mykey.pem
```

### Sign with a label

```bash
sigil sign release.tar.gz --key mykey.pem --label "ci-build-v2.1.0"
```

### Sign with a specific algorithm (ephemeral)

```bash
sigil sign release.tar.gz --algorithm ed25519
```

### Sign with an encrypted key

```bash
sigil sign release.tar.gz --key mykey.pem --passphrase "my-secret"
sigil sign release.tar.gz --key mykey.pem --passphrase-file /secrets/passphrase.txt
```

### Custom output path

```bash
sigil sign release.tar.gz --key mykey.pem --output signatures/release-v2.sig.json
```

---

## 4. Verifying Signatures

### Basic verification (cryptographic only)

```bash
sigil verify release.tar.gz
# Reads release.tar.gz.sig.json automatically
```

### Specify signature file

```bash
sigil verify release.tar.gz --signature path/to/custom.sig.json
```

### Verify with a trust bundle

```bash
sigil verify release.tar.gz --trust-bundle trust.json
```

### Verify with trust bundle + authority

```bash
sigil verify release.tar.gz --trust-bundle trust.json --authority sha256:a1b2c3d4e5f6...
```

### Verify with policy

```bash
sigil verify release.tar.gz --policy policy.json
```

### Verify with discovered trust

```bash
sigil verify release.tar.gz --discover example.com
sigil verify release.tar.gz --discover dns:example.com
sigil verify release.tar.gz --discover git:https://github.com/org/trust-config
```

### Full verification stack (trust + policy + anomaly)

**Bash/Linux/macOS:**
```bash
sigil verify release.tar.gz \
  --trust-bundle trust.json \
  --authority sha256:a1b2c3... \
  --policy policy.json \
  --anomaly \
  --baseline .sigil.baseline.json
```

**PowerShell/Windows:**
```powershell
sigil verify release.tar.gz `
  --trust-bundle trust.json `
  --authority sha256:a1b2c3... `
  --policy policy.json `
  --anomaly `
  --baseline .sigil.baseline.json
```

---

## 5. Multiple Signatures

### Add a second signature to an existing envelope

The second `sigil sign` command appends to the existing `.sig.json`:

```bash
# Build system signs
sigil sign release.tar.gz --key build-key.pem --label "ci-pipeline"

# Security auditor co-signs
sigil sign release.tar.gz --key audit-key.pem --label "security-review"

# Both signatures coexist in release.tar.gz.sig.json
sigil verify release.tar.gz
```

### Multi-algorithm signatures

```bash
# ECDSA signature
sigil sign release.tar.gz --key ecdsa-key.pem --label "primary"

# Post-quantum co-signature for future-proofing
sigil sign release.tar.gz --key mldsa-key.pem --label "post-quantum"
```

---

## 6. Trust Bundles

### Create a trust bundle

```bash
sigil trust create --name "ACME Corp Release Keys" -o acme-trust.json
```

### Add a trusted key

**Bash/Linux/macOS:**
```bash
# Get the fingerprint from a public key
# (shown when you run sigil generate or sigil sign)
sigil trust add acme-trust.json \
  --fingerprint sha256:a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd \
  --name "Build Server Key"
```

**PowerShell/Windows:**
```powershell
# Get the fingerprint from a public key
# (shown when you run sigil generate or sigil sign)
sigil trust add acme-trust.json `
  --fingerprint sha256:a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd `
  --name "Build Server Key"
```

### Add a key with an expiry date

**Bash/Linux/macOS:**
```bash
sigil trust add acme-trust.json \
  --fingerprint sha256:a1b2c3... \
  --name "Contractor Key" \
  --not-after 2026-12-31T23:59:59Z
```

**PowerShell/Windows:**
```powershell
sigil trust add acme-trust.json `
  --fingerprint sha256:a1b2c3... `
  --name "Contractor Key" `
  --not-after 2026-12-31T23:59:59Z
```

### Remove a key

```bash
sigil trust remove acme-trust.json --fingerprint sha256:a1b2c3...
```

### View a trust bundle

```bash
sigil trust show acme-trust.json
```

---

## 7. Key Endorsements

Endorsements let one trusted key vouch for another without making the endorsed key a direct root of trust.

### Add an endorsement

**Bash/Linux/macOS:**
```bash
sigil trust endorse acme-trust.json \
  --endorser sha256:rootkey123... \
  --endorsed sha256:teamkey456... \
  --statement "Approved by security team"
```

**PowerShell/Windows:**
```powershell
sigil trust endorse acme-trust.json `
  --endorser sha256:rootkey123... `
  --endorsed sha256:teamkey456... `
  --statement "Approved by security team"
```

### Endorsement with expiry

**Bash/Linux/macOS:**
```bash
sigil trust endorse acme-trust.json \
  --endorser sha256:rootkey123... \
  --endorsed sha256:contractor789... \
  --statement "Temporary contractor access" \
  --not-after 2026-06-30T00:00:00Z
```

**PowerShell/Windows:**
```powershell
sigil trust endorse acme-trust.json `
  --endorser sha256:rootkey123... `
  --endorsed sha256:contractor789... `
  --statement "Temporary contractor access" `
  --not-after 2026-06-30T00:00:00Z
```

### Scoped endorsement

**Bash/Linux/macOS:**
```bash
sigil trust endorse acme-trust.json \
  --endorser sha256:rootkey123... \
  --endorsed sha256:teamkey456... \
  --scope-names "releases/frontend/*" \
  --scope-labels "ci-pipeline"
```

**PowerShell/Windows:**
```powershell
sigil trust endorse acme-trust.json `
  --endorser sha256:rootkey123... `
  --endorsed sha256:teamkey456... `
  --scope-names "releases/frontend/*" `
  --scope-labels "ci-pipeline"
```

---

## 8. Key Revocation

### Revoke a key

**Bash/Linux/macOS:**
```bash
sigil trust revoke acme-trust.json \
  --fingerprint sha256:compromised123... \
  --reason "Private key compromised on 2026-02-01"
```

**PowerShell/Windows:**
```powershell
sigil trust revoke acme-trust.json `
  --fingerprint sha256:compromised123... `
  --reason "Private key compromised on 2026-02-01"
```

### Temporal revocation behavior

Revocations are temporal. Signatures made **before** the revocation time with a valid RFC 3161 timestamp are still trusted:

```bash
# This artifact was signed and timestamped before the key was revoked
sigil verify old-release.tar.gz --trust-bundle acme-trust.json
# Result: TRUSTED (timestamp proves signing occurred before revocation)

# This artifact was signed after revocation
sigil verify new-release.tar.gz --trust-bundle acme-trust.json
# Result: REVOKED
```

---

## 9. Key Scoping

Scoping restricts which artifacts a key can sign.

### Scope by artifact name pattern

**Bash/Linux/macOS:**
```bash
sigil trust add acme-trust.json \
  --fingerprint sha256:frontend123... \
  --name "Frontend Team Key" \
  --scope-names "releases/frontend/*" \
  --scope-names "releases/shared/*"
```

**PowerShell/Windows:**
```powershell
sigil trust add acme-trust.json `
  --fingerprint sha256:frontend123... `
  --name "Frontend Team Key" `
  --scope-names "releases/frontend/*" `
  --scope-names "releases/shared/*"
```

### Scope by label

**Bash/Linux/macOS:**
```bash
sigil trust add acme-trust.json \
  --fingerprint sha256:cikey123... \
  --name "CI Pipeline Key" \
  --scope-labels "ci-pipeline" \
  --scope-labels "automated-build"
```

**PowerShell/Windows:**
```powershell
sigil trust add acme-trust.json `
  --fingerprint sha256:cikey123... `
  --name "CI Pipeline Key" `
  --scope-labels "ci-pipeline" `
  --scope-labels "automated-build"
```

### Scope by algorithm

**Bash/Linux/macOS:**
```bash
sigil trust add acme-trust.json \
  --fingerprint sha256:pqkey123... \
  --name "Post-Quantum Only Key" \
  --scope-algorithms "ml-dsa-65"
```

**PowerShell/Windows:**
```powershell
sigil trust add acme-trust.json `
  --fingerprint sha256:pqkey123... `
  --name "Post-Quantum Only Key" `
  --scope-algorithms "ml-dsa-65"
```

---

## 10. OIDC Identities in Trust Bundles

### Add a trusted OIDC identity

**Bash/Linux/macOS:**
```bash
# Trust any build from a specific GitHub repo's main branch
sigil trust identity-add acme-trust.json \
  --issuer "https://token.actions.githubusercontent.com" \
  --subject "repo:acme-corp/release-pipeline:ref:refs/heads/main" \
  --name "GitHub Actions - Release Pipeline"
```

**PowerShell/Windows:**
```powershell
# Trust any build from a specific GitHub repo's main branch
sigil trust identity-add acme-trust.json `
  --issuer "https://token.actions.githubusercontent.com" `
  --subject "repo:acme-corp/release-pipeline:ref:refs/heads/main" `
  --name "GitHub Actions - Release Pipeline"
```

### Add with expiry

**Bash/Linux/macOS:**
```bash
sigil trust identity-add acme-trust.json \
  --issuer "https://token.actions.githubusercontent.com" \
  --subject "repo:acme-corp/*:ref:refs/heads/main" \
  --name "GitHub Actions - All Repos" \
  --not-after 2027-01-01T00:00:00Z
```

**PowerShell/Windows:**
```powershell
sigil trust identity-add acme-trust.json `
  --issuer "https://token.actions.githubusercontent.com" `
  --subject "repo:acme-corp/*:ref:refs/heads/main" `
  --name "GitHub Actions - All Repos" `
  --not-after 2027-01-01T00:00:00Z
```

### Remove an OIDC identity

**Bash/Linux/macOS:**
```bash
sigil trust identity-remove acme-trust.json \
  --issuer "https://token.actions.githubusercontent.com" \
  --subject "repo:acme-corp/release-pipeline:ref:refs/heads/main"
```

**PowerShell/Windows:**
```powershell
sigil trust identity-remove acme-trust.json `
  --issuer "https://token.actions.githubusercontent.com" `
  --subject "repo:acme-corp/release-pipeline:ref:refs/heads/main"
```

---

## 11. Trust Bundle Signing

### Sign a trust bundle with an authority key

```bash
sigil trust sign acme-trust.json --key authority-key.pem -o acme-trust-signed.json
```

### Verify specifying the authority

**Bash/Linux/macOS:**
```bash
sigil verify release.tar.gz \
  --trust-bundle acme-trust-signed.json \
  --authority sha256:authorityfingerprint...
```

**PowerShell/Windows:**
```powershell
sigil verify release.tar.gz `
  --trust-bundle acme-trust-signed.json `
  --authority sha256:authorityfingerprint...
```

---

## 12. Discovery

### Publish trust via well-known URL

Host your signed trust bundle at:
```
https://example.com/.well-known/sigil/trust.json
```

### Discover from well-known URL

```bash
sigil discover well-known example.com
sigil discover well-known example.com -o local-trust.json
```

### Publish trust via DNS TXT record

```dns
_sigil.example.com. IN TXT "v=sigil1 bundle=https://example.com/.well-known/sigil/trust.json"
```

### Discover from DNS

```bash
sigil discover dns example.com
sigil discover dns example.com -o local-trust.json
```

### Discover from a Git repository

```bash
sigil discover git https://github.com/acme-corp/trust-config
sigil discover git "https://github.com/acme-corp/trust-config#v2.0" -o local-trust.json
```

### Verify with automatic discovery

```bash
# Well-known (default scheme)
sigil verify release.tar.gz --discover example.com

# DNS scheme
sigil verify release.tar.gz --discover dns:example.com

# Git scheme
sigil verify release.tar.gz --discover git:https://github.com/acme-corp/trust-config
```

---

## 13. SBOM Signing

Sigil auto-detects CycloneDX and SPDX SBOMs, embedding metadata in the signature.

### Sign a CycloneDX SBOM

```bash
sigil sign sbom.cdx.json --key mykey.pem
# Signature includes: sbom.format, sbom.specVersion, sbom.name, etc.
```

### Sign an SPDX SBOM

```bash
sigil sign sbom.spdx.json --key mykey.pem
```

### Verify with SBOM metadata policy

```json
{
  "version": "1.0",
  "rules": [
    { "require": "sbom-metadata", "params": { "keys": ["sbom.format", "sbom.specVersion"] } }
  ]
}
```

```bash
sigil verify sbom.cdx.json --policy sbom-policy.json
```

---

## 14. Manifest Signing (Multi-File)

### Sign all files in a directory

```bash
sigil sign-manifest ./release/ --key mykey.pem
# Output: release/.manifest.sig.json (one atomic signature for all files)
```

### Sign with a glob filter

```bash
sigil sign-manifest ./release/ --include "*.dll" --key mykey.pem
```

### Sign with a label

```bash
sigil sign-manifest ./release/ --key mykey.pem --label "release-v2.1.0"
```

### Custom output path

```bash
sigil sign-manifest ./release/ --key mykey.pem --output signatures/release-manifest.sig.json
```

### Verify a manifest

```bash
sigil verify-manifest release/.manifest.sig.json
```

### Verify with explicit base path

```bash
sigil verify-manifest signatures/release-manifest.sig.json --base-path ./release/
```

### Verify with trust

```bash
sigil verify-manifest release/.manifest.sig.json --trust-bundle trust.json
```

---

## 15. Archive Signing

### Sign a ZIP archive

```bash
sigil sign-archive release.zip --key mykey.pem
# Output: release.zip.archive.sig.json (includes per-entry digests)
```

### Sign a tar.gz archive

```bash
sigil sign-archive release.tar.gz --key mykey.pem
```

### Sign a NuGet package

```bash
sigil sign-archive MyLibrary.1.0.0.nupkg --key mykey.pem
# Detects NuGet metadata automatically
```

### Verify an archive

```bash
sigil verify-archive release.zip
# Detects tampered or added entries
```

### Verify with trust

```bash
sigil verify-archive release.zip --trust-bundle trust.json --policy policy.json
```

---

## 16. Container/OCI Image Signing

### Sign a container image

```bash
sigil sign-image ghcr.io/acme/myapp:v1.0 --key mykey.pem
```

### Sign with keyless (CI/CD)

```bash
sigil sign-image ghcr.io/acme/myapp:v1.0 --keyless --timestamp https://freetsa.org/tsr
```

### Sign with vault

```bash
sigil sign-image ghcr.io/acme/myapp:v1.0 --vault azure --vault-key my-signing-key
```

### Verify a container image

```bash
sigil verify-image ghcr.io/acme/myapp:v1.0
```

### Verify with trust + policy

**Bash/Linux/macOS:**
```bash
sigil verify-image ghcr.io/acme/myapp:v1.0 \
  --trust-bundle trust.json \
  --policy container-policy.json
```

**PowerShell/Windows:**
```powershell
sigil verify-image ghcr.io/acme/myapp:v1.0 `
  --trust-bundle trust.json `
  --policy container-policy.json
```

---

## 17. PE Binary Signing (Authenticode)

### Sign a Windows executable

```bash
sigil sign-pe MyApp.exe --key code-signing.pfx --passphrase "my-password"
# Produces: embedded Authenticode signature + MyApp.exe.sig.json envelope
```

### Sign from Windows Certificate Store

```bash
sigil sign-pe MyApp.exe --cert-store abc123def456...
```

### Sign with timestamp

**Bash/Linux/macOS:**
```bash
sigil sign-pe MyApp.exe --key code-signing.pfx --passphrase "pw" \
  --timestamp http://timestamp.digicert.com
```

**PowerShell/Windows:**
```powershell
sigil sign-pe MyApp.exe --key code-signing.pfx --passphrase "pw" `
  --timestamp http://timestamp.digicert.com
```

### Sign to a different output file

```bash
sigil sign-pe MyApp.exe --key code-signing.pfx --output MyApp-signed.exe
```

### Verify a PE binary

```bash
sigil verify-pe MyApp.exe
# Checks both Authenticode and Sigil envelope
```

### Verify with trust

```bash
sigil verify-pe MyApp.exe --trust-bundle trust.json
```

### Cross-platform PE signing

Sigil's PE signing is pure managed code — sign Windows binaries on Linux or macOS:

```bash
# On Linux
sigil sign-pe WindowsApp.exe --key code-signing.pfx --passphrase "pw"
```

---

## 18. Git Commit Signing

### Configure Sigil as your git signing tool

```bash
# Generate a key
sigil generate -o git-signing-key

# Configure globally
sigil git config --key git-signing-key.pem --global
```

### Configure with vault

```bash
sigil git config --vault hashicorp --vault-key transit/git-key --global
```

### Configure with Windows Certificate Store

```bash
sigil git config --cert-store abc123def456... --global
```

### After configuration, git works normally

```bash
git commit -m "signed commit"
git tag -s v1.0 -m "signed tag"
git log --show-signature
```

---

## 19. Attestations

### Create a SLSA provenance attestation

**Bash/Linux/macOS:**
```bash
# Create a predicate file
cat > provenance.json << 'EOF'
{
  "buildType": "https://github.com/acme-corp/build-system@v1",
  "builder": { "id": "https://github.com/acme-corp/build-system" },
  "invocation": { "configSource": { "uri": "https://github.com/acme-corp/myapp" } }
}
EOF

# Create the attestation
sigil attest release.tar.gz \
  --predicate provenance.json \
  --type slsa-provenance-v1 \
  --key build-key.pem
# Output: release.tar.gz.att.json
```

**PowerShell/Windows:**
```powershell
# Create a predicate file
@'
{
  "buildType": "https://github.com/acme-corp/build-system@v1",
  "builder": { "id": "https://github.com/acme-corp/build-system" },
  "invocation": { "configSource": { "uri": "https://github.com/acme-corp/myapp" } }
}
'@ | Set-Content provenance.json -Encoding UTF8

# Create the attestation
sigil attest release.tar.gz `
  --predicate provenance.json `
  --type slsa-provenance-v1 `
  --key build-key.pem
# Output: release.tar.gz.att.json
```

### Create a custom attestation

**Bash/Linux/macOS:**
```bash
sigil attest release.tar.gz \
  --predicate scan-results.json \
  --type https://example.com/vulnerability-scan/v1 \
  --key scanner-key.pem
```

**PowerShell/Windows:**
```powershell
sigil attest release.tar.gz `
  --predicate scan-results.json `
  --type https://example.com/vulnerability-scan/v1 `
  --key scanner-key.pem
```

### Multi-party attestation (append)

```bash
# First attestor
sigil attest release.tar.gz --predicate build-info.json --type slsa-provenance-v1 --key build-key.pem

# Second attestor adds their signature
sigil attest release.tar.gz --predicate build-info.json --type slsa-provenance-v1 --key audit-key.pem
```

### Verify an attestation

```bash
sigil verify-attestation release.tar.gz
```

### Verify with type filter

```bash
sigil verify-attestation release.tar.gz --type slsa-provenance-v1
```

### Verify with trust + policy

**Bash/Linux/macOS:**
```bash
sigil verify-attestation release.tar.gz \
  --trust-bundle trust.json \
  --policy attestation-policy.json
```

**PowerShell/Windows:**
```powershell
sigil verify-attestation release.tar.gz `
  --trust-bundle trust.json `
  --policy attestation-policy.json
```

---

## 20. Environment Fingerprint Attestation

### Capture build environment

```bash
sigil attest-env release.tar.gz --key build-key.pem
# Output: release.tar.gz.env-attestation.json
# Captures: OS, architecture, .NET version, CPU count, CI metadata
```

### Include custom environment variables

**Bash/Linux/macOS:**
```bash
sigil attest-env release.tar.gz --key build-key.pem \
  --include-var "DOTNET_*" \
  --include-var "BUILD_*" \
  --include-var "NODE_VERSION"
```

**PowerShell/Windows:**
```powershell
sigil attest-env release.tar.gz --key build-key.pem `
  --include-var "DOTNET_*" `
  --include-var "BUILD_*" `
  --include-var "NODE_VERSION"
```

Sensitive variables (containing AUTH, PASSWORD, SECRET, KEY, TOKEN, etc.) are automatically filtered out.

### Keyless environment attestation (CI/CD)

```bash
sigil attest-env release.tar.gz --keyless --timestamp https://freetsa.org/tsr
```

### Verify environment attestation

**Bash/Linux/macOS:**
```bash
sigil verify-attestation release.tar.gz \
  --attestation release.tar.gz.env-attestation.json \
  --type env-fingerprint
```

**PowerShell/Windows:**
```powershell
sigil verify-attestation release.tar.gz `
  --attestation release.tar.gz.env-attestation.json `
  --type env-fingerprint
```

---

## 21. Policy Enforcement

### Create a policy file

```json
{
  "version": "1.0",
  "rules": [
    { "require": "min-signatures", "params": { "count": 2 } },
    { "require": "timestamp" },
    { "require": "algorithm", "params": { "allowed": ["ecdsa-p256", "ecdsa-p384"] } },
    { "require": "trusted" },
    { "require": "label", "params": { "pattern": "ci-*" } }
  ]
}
```

### Apply a policy during verification

```bash
sigil verify release.tar.gz --trust-bundle trust.json --policy policy.json
```

### Require transparency log entry

```json
{
  "version": "1.0",
  "rules": [
    { "require": "logged" },
    { "require": "trusted" }
  ]
}
```

### Require specific key

```json
{
  "version": "1.0",
  "rules": [
    { "require": "key", "params": { "fingerprint": "sha256:a1b2c3..." } }
  ]
}
```

### Require SBOM metadata

```json
{
  "version": "1.0",
  "rules": [
    { "require": "sbom-metadata", "params": { "keys": ["sbom.format", "sbom.name", "sbom.componentCount"] } }
  ]
}
```

### Policy rules reference

| Rule | Description | Params |
|------|-------------|--------|
| `min-signatures` | Minimum valid signatures | `count` (integer) |
| `timestamp` | Require RFC 3161 timestamp | -- |
| `algorithm` | Restrict to approved algorithms | `allowed` (list) |
| `trusted` | At least one trusted signature | -- |
| `key` | Require specific key | `fingerprint` (string) |
| `label` | Require matching label | `pattern` (glob) |
| `sbom-metadata` | Require SBOM metadata fields | `keys` (list) |
| `logged` | Require transparency log receipt | -- |

---

## 22. RFC 3161 Timestamping

### Sign with a timestamp

```bash
sigil sign release.tar.gz --key mykey.pem --timestamp http://timestamp.digicert.com
```

### Add timestamp to existing signature

```bash
sigil timestamp release.tar.gz.sig.json --tsa http://timestamp.digicert.com
```

### Timestamp a specific signature index

```bash
sigil timestamp release.tar.gz.sig.json --tsa http://timestamp.digicert.com --index 1
```

### Free TSA servers

```bash
# DigiCert
sigil sign release.tar.gz --key mykey.pem --timestamp http://timestamp.digicert.com

# FreeTSA
sigil sign release.tar.gz --key mykey.pem --timestamp https://freetsa.org/tsr
```

### Why timestamp?

Timestamps prove **when** a signature was made. This enables:
- Signatures that remain valid after key expiry
- Signatures that remain valid after key revocation (if signed before revocation)
- Compliance with long-term archival requirements

---

## 23. Transparency Logs

### Append to local log

```bash
sigil sign release.tar.gz --key mykey.pem
sigil log append release.tar.gz.sig.json
# Appends to .sigil.log.jsonl (Merkle tree)
```

### Append to custom log file

```bash
sigil log append release.tar.gz.sig.json --log audit/signing.log.jsonl
```

### Verify log integrity

```bash
sigil log verify
sigil log verify --log audit/signing.log.jsonl
```

### Verify with checkpoint

```bash
sigil log verify --checkpoint last-audit-checkpoint.json
```

### Search log entries

```bash
# By key fingerprint
sigil log search --key sha256:a1b2c3...

# By artifact name
sigil log search --artifact release.tar.gz

# By digest
sigil log search --digest sha256:deadbeef...
```

### Show log entries

```bash
sigil log show
sigil log show --limit 10
sigil log show --offset 50 --limit 10
```

### Generate proofs

```bash
# Inclusion proof for a specific entry
sigil log proof --index 42

# Consistency proof between tree sizes
sigil log proof --old-size 100
```

---

## 24. Remote Transparency Logs

### Sign with Rekor (Sigstore public log)

```bash
sigil sign release.tar.gz --key mykey.pem --log-url rekor
```

### Sign with custom Rekor instance

```bash
sigil sign release.tar.gz --key mykey.pem --log-url rekor:https://rekor.internal.example.com
```

### Sign with Sigil LogServer

**Bash/Linux/macOS:**
```bash
sigil sign release.tar.gz --key mykey.pem \
  --log-url https://log.example.com \
  --log-api-key my-secret-api-key
```

**PowerShell/Windows:**
```powershell
sigil sign release.tar.gz --key mykey.pem `
  --log-url https://log.example.com `
  --log-api-key my-secret-api-key
```

### Enforce logging via policy

```json
{
  "version": "1.0",
  "rules": [
    { "require": "logged" }
  ]
}
```

---

## 25. Keyless/OIDC Signing

### GitHub Actions (auto-detected)

```bash
# In a GitHub Actions workflow — OIDC token is auto-detected
sigil sign release.tar.gz --keyless --timestamp https://freetsa.org/tsr
```

### GitLab CI (auto-detected)

```bash
# In a GitLab CI pipeline — CI_JOB_JWT is auto-detected
sigil sign release.tar.gz --keyless --timestamp https://freetsa.org/tsr
```

### Manual OIDC token

**Bash/Linux/macOS:**
```bash
sigil sign release.tar.gz --keyless \
  --oidc-token "eyJhbGci..." \
  --timestamp https://freetsa.org/tsr
```

**PowerShell/Windows:**
```powershell
sigil sign release.tar.gz --keyless `
  --oidc-token "eyJhbGci..." `
  --timestamp https://freetsa.org/tsr
```

### Trust keyless signatures via OIDC identities

**Bash/Linux/macOS:**
```bash
# Add trusted identity to bundle
sigil trust identity-add trust.json \
  --issuer "https://token.actions.githubusercontent.com" \
  --subject "repo:acme-corp/myapp:ref:refs/heads/main"

# Verify — matches OIDC identity in signature
sigil verify release.tar.gz --trust-bundle trust.json
# Result: TRUSTED VIA OIDC
```

**PowerShell/Windows:**
```powershell
# Add trusted identity to bundle
sigil trust identity-add trust.json `
  --issuer "https://token.actions.githubusercontent.com" `
  --subject "repo:acme-corp/myapp:ref:refs/heads/main"

# Verify — matches OIDC identity in signature
sigil verify release.tar.gz --trust-bundle trust.json
# Result: TRUSTED VIA OIDC
```

---

## 26. Vault-Backed Signing

### HashiCorp Vault

```bash
sigil sign release.tar.gz --vault hashicorp --vault-key transit/my-signing-key
```

### Azure Key Vault

```bash
sigil sign release.tar.gz --vault azure --vault-key my-signing-key
```

### AWS KMS

```bash
sigil sign release.tar.gz --vault aws --vault-key alias/my-signing-key
```

### Google Cloud KMS

**Bash/Linux/macOS:**
```bash
sigil sign release.tar.gz --vault gcp \
  --vault-key "projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key/cryptoKeyVersions/1"
```

**PowerShell/Windows:**
```powershell
sigil sign release.tar.gz --vault gcp `
  --vault-key "projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key/cryptoKeyVersions/1"
```

### Vault signing for manifests

```bash
sigil sign-manifest ./release/ --vault azure --vault-key my-key --label "release-v2"
```

### Vault signing for container images

```bash
sigil sign-image ghcr.io/acme/app:v1 --vault aws --vault-key alias/container-key
```

---

## 27. Hardware Tokens (PKCS#11)

### Sign with a hardware token

**Bash/Linux/macOS:**
```bash
sigil sign release.tar.gz --vault pkcs11 \
  --vault-key "pkcs11:token=YubiKey;object=my-signing-key"
```

**PowerShell/Windows:**
```powershell
sigil sign release.tar.gz --vault pkcs11 `
  --vault-key "pkcs11:token=YubiKey;object=my-signing-key"
```

### Sign with a specific PKCS#11 library

**Bash/Linux/macOS:**
```bash
sigil sign release.tar.gz --vault pkcs11 \
  --vault-key "pkcs11:token=HSM;object=release-key;module-path=/usr/lib/softhsm/libsofthsm2.so"
```

**PowerShell/Windows:**
```powershell
sigil sign release.tar.gz --vault pkcs11 `
  --vault-key "pkcs11:token=HSM;object=release-key;module-path=C:\Program Files\SoftHSM2\lib\softhsm2.dll"
```

---

## 28. Windows Certificate Store

### Sign using a certificate from the store

```bash
# Use certificate thumbprint
sigil sign release.tar.gz --cert-store abc123def456789...
```

### Specify store location

```bash
# Current user (default)
sigil sign release.tar.gz --cert-store abc123... --store-location CurrentUser

# Local machine (requires admin)
sigil sign release.tar.gz --cert-store abc123... --store-location LocalMachine
```

### Use cert store for PE signing

```bash
sigil sign-pe MyApp.exe --cert-store abc123...
```

### Use cert store for trust bundle signing

```bash
sigil trust sign trust.json --cert-store abc123... -o trust-signed.json
```

---

## 29. PFX/PKCS#12 Certificates

### Sign with a PFX file

```bash
sigil sign release.tar.gz --key signing-cert.pfx --passphrase "my-password"
```

### PFX for PE signing

```bash
sigil sign-pe MyApp.exe --key code-signing.pfx --passphrase "pw"
```

---

## 30. Passphrase Management

Sigil resolves passphrases in this order:
1. `--passphrase` CLI argument
2. `--passphrase-file` file path
3. `SIGIL_PASSPHRASE` environment variable
4. Windows Credential Manager (if available)
5. Interactive prompt

### Store a passphrase in Windows Credential Manager

```bash
sigil credential store
# Prompts for key name and passphrase
```

### Remove a stored passphrase

```bash
sigil credential remove
```

### List stored passphrases

```bash
sigil credential list
```

### Use environment variable

**Bash/Linux/macOS:**
```bash
export SIGIL_PASSPHRASE="my-secret"
sigil sign release.tar.gz --key encrypted-key.pem
```

**PowerShell/Windows:**
```powershell
$env:SIGIL_PASSPHRASE = "my-secret"
sigil sign release.tar.gz --key encrypted-key.pem
```

---

## 31. Trust Graph

### Build a trust graph from a directory

```bash
sigil graph build --scan ./release --output graph.json
# Ingests: .sig.json, .manifest.sig.json, .archive.sig.json, .att.json, trust.json
```

### Query: What did a key sign?

```bash
sigil graph query --graph graph.json --key sha256:a1b2c3... --signed-by
```

### Query: Trust chain for an artifact

```bash
sigil graph query --graph graph.json --artifact mylib.dll --chain
```

### Query: Reachability from a key

```bash
sigil graph query --graph graph.json --key sha256:a1b2c3... --reach
```

### Query: Shortest path between nodes

**Bash/Linux/macOS:**
```bash
sigil graph query --graph graph.json \
  --from "artifact:mylib.dll" \
  --to "key:sha256:d4e5f6..." \
  --path
```

**PowerShell/Windows:**
```powershell
sigil graph query --graph graph.json `
  --from "artifact:mylib.dll" `
  --to "key:sha256:d4e5f6..." `
  --path
```

### Query: Impact of a revoked key

```bash
sigil graph query --graph graph.json --revoked --impact
```

### Export to Graphviz DOT

```bash
sigil graph export --graph graph.json --format dot --output graph.dot
dot -Tpng graph.dot -o graph.png
```

### Export to JSON

```bash
sigil graph export --graph graph.json --format json --output graph-export.json
```

---

## 32. Key Compromise Impact Analysis

### Analyze impact from a fingerprint

```bash
sigil impact --fingerprint sha256:a1b2c3... --scan ./release
```

### Analyze from a public key file

```bash
sigil impact --key compromised-key.pub.pem --scan ./release
```

### Use a pre-built graph

```bash
sigil impact --fingerprint sha256:a1b2c3... --graph graph.json
```

### JSON output for SIEM integration

**Bash/Linux/macOS:**
```bash
sigil impact --fingerprint sha256:a1b2c3... --graph graph.json \
  --format json --output impact-report.json
```

**PowerShell/Windows:**
```powershell
sigil impact --fingerprint sha256:a1b2c3... --graph graph.json `
  --format json --output impact-report.json
```

### What the report shows

- **Direct artifacts**: Files signed by the compromised key
- **Endorsed keys**: Keys trusted via endorsement chain from the compromised key
- **Transitive artifacts**: Files signed by endorsed keys (blast radius)
- **Recommended actions**: Revocation steps

---

## 33. Time Travel Verification

### Verify trust status at a past date

```bash
# What was the trust status when we deployed v3.2.0 on March 3, 2025?
sigil verify app-v3.2.0.tar.gz --trust-bundle trust.json --at 2025-03-03
```

### ISO 8601 full timestamp

```bash
sigil verify app.tar.gz --trust-bundle trust.json --at 2025-06-15T14:30:00Z
```

### Incident response: before vs after revocation

```bash
# Before the key was revoked (2025-02-01) — should show TRUSTED
sigil verify critical-service.dll --trust-bundle trust.json --at 2025-02-01

# Current time — should show REVOKED
sigil verify critical-service.dll --trust-bundle trust.json
```

### Time travel works on all verify commands

```bash
sigil verify release.tar.gz --trust-bundle trust.json --at 2025-06-15
sigil verify-attestation release.tar.gz --trust-bundle trust.json --at 2025-06-15
sigil verify-manifest manifest.sig.json --trust-bundle trust.json --at 2025-06-15
sigil verify-archive release.zip --trust-bundle trust.json --at 2025-06-15
sigil verify-pe MyApp.exe --trust-bundle trust.json --at 2025-06-15
sigil verify-image ghcr.io/acme/app:v1 --trust-bundle trust.json --at 2025-06-15
```

---

## 34. Anomaly Detection

### Learn a baseline from existing signatures

```bash
sigil baseline learn --scan ./release
# Output: ./release/.sigil.baseline.json
```

### Learn with custom output

```bash
sigil baseline learn --scan ./release --output baselines/release-baseline.json
```

### Verify with anomaly detection

```bash
sigil verify release.tar.gz --anomaly
# Uses .sigil.baseline.json in artifact directory
```

### Verify with explicit baseline

```bash
sigil verify release.tar.gz --anomaly --baseline baselines/release-baseline.json
```

### Anomaly rules

| Rule | Severity | Triggers when |
|------|----------|---------------|
| UnknownSigner | Warning | Key fingerprint not in baseline |
| UnknownOidcIdentity | Critical | OIDC issuer/identity never seen before |
| OffHoursSigning | Warning | Signing hour outside learned range |
| UnknownAlgorithm | Warning | Algorithm not in baseline |
| UnknownLabel | Info | Label not in baseline |

---

## 35. CI/CD Recipes

### GitHub Actions — Full Pipeline

```yaml
name: Sign and Publish
on:
  push:
    tags: ['v*']

permissions:
  id-token: write  # Required for keyless signing
  contents: read

jobs:
  build-sign:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build
        run: dotnet publish -c Release -o ./publish

      - name: Sign release
        run: |
          sigil sign-manifest ./publish/ \
            --keyless \
            --timestamp https://freetsa.org/tsr \
            --label "github-actions" \
            --log-url rekor

      - name: Create environment attestation
        run: |
          sigil attest-env ./publish/ \
            --keyless \
            --timestamp https://freetsa.org/tsr \
            --include-var "DOTNET_*" \
            --include-var "GITHUB_*"

      - name: Verify
        run: |
          sigil verify-manifest ./publish/.manifest.sig.json
```

### GitHub Actions — Container Signing

```yaml
jobs:
  build-push-sign:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build and push image
        run: |
          docker build -t ghcr.io/${{ github.repository }}:${{ github.ref_name }} .
          docker push ghcr.io/${{ github.repository }}:${{ github.ref_name }}

      - name: Sign image
        run: |
          sigil sign-image ghcr.io/${{ github.repository }}:${{ github.ref_name }} \
            --keyless \
            --timestamp https://freetsa.org/tsr \
            --log-url rekor
```

### GitLab CI — Keyless Signing

```yaml
sign-release:
  image: mcr.microsoft.com/dotnet/sdk:10.0
  id_tokens:
    SIGIL_ID_TOKEN:
      aud: sigil
  script:
    - sigil sign release.tar.gz --keyless --timestamp https://freetsa.org/tsr
    - sigil verify release.tar.gz
  artifacts:
    paths:
      - release.tar.gz.sig.json
```

### GitLab CI — With Vault

```yaml
sign-release:
  image: mcr.microsoft.com/dotnet/sdk:10.0
  variables:
    VAULT_ADDR: https://vault.internal.example.com
  script:
    - sigil sign release.tar.gz --vault hashicorp --vault-key transit/release-key
    - sigil verify release.tar.gz --trust-bundle trust.json
```

### Azure DevOps — With Key Vault

```yaml
steps:
  - task: DotNetCoreCLI@2
    displayName: 'Sign release'
    inputs:
      command: 'custom'
      custom: 'sigil'
      arguments: 'sign release.tar.gz --vault azure --vault-key release-signing-key'
```

---

## 36. Enterprise Scenarios

### Scenario: Multi-Team Release Pipeline

**Bash/Linux/macOS:**
```bash
# 1. Create org-wide trust bundle
sigil trust create --name "ACME Corp" -o acme-trust.json

# 2. Add team keys with scoping
sigil trust add acme-trust.json \
  --fingerprint sha256:frontend... \
  --name "Frontend Team" \
  --scope-names "releases/frontend/*"

sigil trust add acme-trust.json \
  --fingerprint sha256:backend... \
  --name "Backend Team" \
  --scope-names "releases/backend/*"

sigil trust add acme-trust.json \
  --fingerprint sha256:security... \
  --name "Security Team"
  # No scope — can sign anything

# 3. Sign the trust bundle
sigil trust sign acme-trust.json --key authority.pem -o acme-trust-signed.json

# 4. Publish via well-known URL
cp acme-trust-signed.json /var/www/.well-known/sigil/trust.json

# 5. Teams sign their releases
sigil sign releases/frontend/app.js --key frontend-key.pem --label "frontend-v2"
sigil sign releases/backend/api.dll --key backend-key.pem --label "backend-v3"

# 6. Security team co-signs after review
sigil sign releases/frontend/app.js --key security-key.pem --label "security-review"

# 7. Deploy-time verification
sigil verify releases/frontend/app.js --discover example.com --policy release-policy.json
```

**PowerShell/Windows:**
```powershell
# 1. Create org-wide trust bundle
sigil trust create --name "ACME Corp" -o acme-trust.json

# 2. Add team keys with scoping
sigil trust add acme-trust.json `
  --fingerprint sha256:frontend... `
  --name "Frontend Team" `
  --scope-names "releases/frontend/*"

sigil trust add acme-trust.json `
  --fingerprint sha256:backend... `
  --name "Backend Team" `
  --scope-names "releases/backend/*"

sigil trust add acme-trust.json `
  --fingerprint sha256:security... `
  --name "Security Team"
  # No scope — can sign anything

# 3. Sign the trust bundle
sigil trust sign acme-trust.json --key authority.pem -o acme-trust-signed.json

# 4. Publish via well-known URL
Copy-Item acme-trust-signed.json C:\inetpub\wwwroot\.well-known\sigil\trust.json

# 5. Teams sign their releases
sigil sign releases/frontend/app.js --key frontend-key.pem --label "frontend-v2"
sigil sign releases/backend/api.dll --key backend-key.pem --label "backend-v3"

# 6. Security team co-signs after review
sigil sign releases/frontend/app.js --key security-key.pem --label "security-review"

# 7. Deploy-time verification
sigil verify releases/frontend/app.js --discover example.com --policy release-policy.json
```

### Scenario: Golden Image Enforcement

**Bash/Linux/macOS:**
```bash
# Build step — sign + capture environment
sigil sign release.tar.gz --key build-key.pem --label "ci-build"
sigil attest-env release.tar.gz --key build-key.pem --include-var "DOTNET_*"

# Deploy step — verify both
sigil verify release.tar.gz --trust-bundle trust.json
sigil verify-attestation release.tar.gz \
  --attestation release.tar.gz.env-attestation.json \
  --type env-fingerprint \
  --trust-bundle trust.json
```

**PowerShell/Windows:**
```powershell
# Build step — sign + capture environment
sigil sign release.tar.gz --key build-key.pem --label "ci-build"
sigil attest-env release.tar.gz --key build-key.pem --include-var "DOTNET_*"

# Deploy step — verify both
sigil verify release.tar.gz --trust-bundle trust.json
sigil verify-attestation release.tar.gz `
  --attestation release.tar.gz.env-attestation.json `
  --type env-fingerprint `
  --trust-bundle trust.json
```

### Scenario: Incident Response — Key Compromise

**Bash/Linux/macOS:**
```bash
# 1. Assess blast radius
sigil impact --fingerprint sha256:compromised... --scan ./all-releases --format json --output impact.json

# 2. Revoke the key
sigil trust revoke trust.json --fingerprint sha256:compromised... --reason "Key compromised 2026-02-12"
sigil trust sign trust.json --key authority.pem -o trust-signed.json

# 3. Re-publish trust bundle
cp trust-signed.json /var/www/.well-known/sigil/trust.json

# 4. Verify historical releases (before compromise)
sigil verify old-release.tar.gz --trust-bundle trust-signed.json --at 2026-01-15
# Result: TRUSTED (timestamped before revocation)

# 5. Verify recent releases (during compromise window)
sigil verify suspect-release.tar.gz --trust-bundle trust-signed.json
# Result: REVOKED
```

**PowerShell/Windows:**
```powershell
# 1. Assess blast radius
sigil impact --fingerprint sha256:compromised... --scan ./all-releases --format json --output impact.json

# 2. Revoke the key
sigil trust revoke trust.json --fingerprint sha256:compromised... --reason "Key compromised 2026-02-12"
sigil trust sign trust.json --key authority.pem -o trust-signed.json

# 3. Re-publish trust bundle
Copy-Item trust-signed.json C:\inetpub\wwwroot\.well-known\sigil\trust.json

# 4. Verify historical releases (before compromise)
sigil verify old-release.tar.gz --trust-bundle trust-signed.json --at 2026-01-15
# Result: TRUSTED (timestamped before revocation)

# 5. Verify recent releases (during compromise window)
sigil verify suspect-release.tar.gz --trust-bundle trust-signed.json
# Result: REVOKED
```

### Scenario: Compliance Audit

```bash
# Build the trust graph from all artifacts
sigil graph build --scan /var/artifacts --output audit-graph.json

# Export for visualization
sigil graph export --graph audit-graph.json --format dot --output audit.dot

# Query: what did each key sign?
sigil graph query --graph audit-graph.json --key sha256:key1... --signed-by
sigil graph query --graph audit-graph.json --key sha256:key2... --signed-by

# Verify historical trust status
sigil verify critical-app.tar.gz --trust-bundle trust.json --at 2025-12-31

# Run anomaly detection
sigil baseline learn --scan /var/artifacts
sigil verify critical-app.tar.gz --anomaly
```

### Scenario: Air-Gapped Environment

```bash
# On connected machine — generate keys, create trust bundle
sigil generate -o airgap-key
sigil trust create --name "Air-Gap Trust" -o airgap-trust.json
sigil trust add airgap-trust.json --fingerprint sha256:...

# Transfer key + trust bundle via secure media

# On air-gapped machine — sign
sigil sign firmware.bin --key airgap-key.pem

# Verify (no network needed — all data is local)
sigil verify firmware.bin --trust-bundle airgap-trust.json
```

### Scenario: Supply Chain Policy with SBOM

**Bash/Linux/macOS:**
```bash
# Policy: require SBOM metadata, 2 signatures, timestamp, and trusted signer
cat > supply-chain-policy.json << 'EOF'
{
  "version": "1.0",
  "rules": [
    { "require": "min-signatures", "params": { "count": 2 } },
    { "require": "timestamp" },
    { "require": "trusted" },
    { "require": "sbom-metadata", "params": { "keys": ["sbom.format", "sbom.name", "sbom.componentCount"] } },
    { "require": "algorithm", "params": { "allowed": ["ecdsa-p256", "ecdsa-p384", "ed25519"] } }
  ]
}
EOF

# Sign the SBOM
sigil sign sbom.cdx.json --key build-key.pem --timestamp https://freetsa.org/tsr --label "build"
sigil sign sbom.cdx.json --key audit-key.pem --timestamp https://freetsa.org/tsr --label "audit"

# Verify against policy
sigil verify sbom.cdx.json --trust-bundle trust.json --policy supply-chain-policy.json
```

**PowerShell/Windows:**
```powershell
# Policy: require SBOM metadata, 2 signatures, timestamp, and trusted signer
@'
{
  "version": "1.0",
  "rules": [
    { "require": "min-signatures", "params": { "count": 2 } },
    { "require": "timestamp" },
    { "require": "trusted" },
    { "require": "sbom-metadata", "params": { "keys": ["sbom.format", "sbom.name", "sbom.componentCount"] } },
    { "require": "algorithm", "params": { "allowed": ["ecdsa-p256", "ecdsa-p384", "ed25519"] } }
  ]
}
'@ | Set-Content supply-chain-policy.json -Encoding UTF8

# Sign the SBOM
sigil sign sbom.cdx.json --key build-key.pem --timestamp https://freetsa.org/tsr --label "build"
sigil sign sbom.cdx.json --key audit-key.pem --timestamp https://freetsa.org/tsr --label "audit"

# Verify against policy
sigil verify sbom.cdx.json --trust-bundle trust.json --policy supply-chain-policy.json
```

---

## 37. Secure Passphrase Handling

Sigil resolves passphrases through a priority chain. **Never pass secrets as CLI arguments in production** — they appear in process listings and shell history.

### Priority chain (highest to lowest)

| Priority | Method | Security | Recommended For |
|----------|--------|----------|-----------------|
| 1 | `--passphrase "..."` | Visible in process list and shell history | Local dev only |
| 2 | `--passphrase-file /path` | File on disk — control permissions | CI/CD mounted secrets |
| 3 | `SIGIL_PASSPHRASE` env var | In-memory only | CI/CD pipelines |
| 4 | `SIGIL_PASSPHRASE_FILE` env var | Points to file — control permissions | CI/CD mounted secrets |
| 5 | Windows Credential Manager | DPAPI-protected, per-user | Developer workstations |
| 6 | Interactive prompt | Never stored | Manual signing |

### Use environment variables (CI/CD)

**Bash/Linux/macOS:**
```bash
# Set the passphrase via environment variable
export SIGIL_PASSPHRASE="my-secret-passphrase"

# Sigil picks it up automatically — no --passphrase flag needed
sigil sign release.tar.gz --key mykey.pem
```

**PowerShell/Windows:**
```powershell
# Set the passphrase via environment variable
$env:SIGIL_PASSPHRASE = "my-secret-passphrase"

# Sigil picks it up automatically — no --passphrase flag needed
sigil sign release.tar.gz --key mykey.pem
```

### Use a passphrase file (CI/CD with mounted secrets)

**Bash/Linux/macOS:**
```bash
# Kubernetes: mount secret as file
# Docker: mount secret at /run/secrets/sigil-passphrase

# Option A: CLI flag
sigil sign release.tar.gz --key mykey.pem --passphrase-file /run/secrets/sigil-passphrase

# Option B: Environment variable pointing to file
export SIGIL_PASSPHRASE_FILE="/run/secrets/sigil-passphrase"
sigil sign release.tar.gz --key mykey.pem
```

**PowerShell/Windows:**
```powershell
# Option A: CLI flag
sigil sign release.tar.gz --key mykey.pem --passphrase-file C:\secrets\sigil-passphrase.txt

# Option B: Environment variable pointing to file
$env:SIGIL_PASSPHRASE_FILE = "C:\secrets\sigil-passphrase.txt"
sigil sign release.tar.gz --key mykey.pem
```

### Use Windows Credential Manager (developer workstation)

```bash
# Store once
sigil credential store
# Prompts for: key path and passphrase

# From now on, Sigil retrieves the passphrase automatically
sigil sign release.tar.gz --key C:\keys\mykey.pem
# No --passphrase needed — resolved from Credential Manager
```

### Security notes

- Passphrase files: Sigil strips UTF-8 BOM and trailing newlines, then zeros the file bytes from memory
- Environment variables: cleared from Sigil's process memory after use
- Windows Credential Manager: protected by DPAPI (user-scoped encryption)
- **Never commit passphrase files to version control**

---

## 38. Environment Variables Reference

### Sigil-specific variables

| Variable | Purpose | Used by |
|----------|---------|---------|
| `SIGIL_PASSPHRASE` | Private key passphrase | All signing commands |
| `SIGIL_PASSPHRASE_FILE` | Path to passphrase file | All signing commands |
| `SIGIL_REGISTRY_USERNAME` | OCI registry username | `sign-image`, `verify-image` |
| `SIGIL_REGISTRY_PASSWORD` | OCI registry password | `sign-image`, `verify-image` |
| `SIGIL_ID_TOKEN` | Pre-acquired OIDC token (GitLab CI) | `--keyless` signing |
| `SIGIL_API_KEY` | Log server API key | Log server |

### Vault provider variables

| Variable | Purpose | Provider |
|----------|---------|----------|
| `VAULT_ADDR` | HashiCorp Vault URL (HTTPS enforced) | `--vault hashicorp` |
| `VAULT_TOKEN` | Vault authentication token | `--vault hashicorp` |
| `VAULT_ROLE_ID` | AppRole role ID | `--vault hashicorp` |
| `VAULT_SECRET_ID` | AppRole secret ID | `--vault hashicorp` |
| `VAULT_NAMESPACE` | Vault namespace (enterprise) | `--vault hashicorp` |
| `VAULT_MOUNT_PATH` | Transit engine mount (default: `transit`) | `--vault hashicorp` |
| `AZURE_KEY_VAULT_URL` | Azure Key Vault URL (HTTPS enforced) | `--vault azure` |
| `AWS_REGION` | AWS region for KMS | `--vault aws` |
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to GCP service account JSON | `--vault gcp` |
| `PKCS11_LIBRARY` | Path to PKCS#11 library (.so/.dll) | `--vault pkcs11` |
| `PKCS11_PIN` | Hardware token PIN | `--vault pkcs11` |

### CI/CD auto-detected variables

| Variable | Purpose | CI Provider |
|----------|---------|-------------|
| `ACTIONS_ID_TOKEN_REQUEST_URL` | OIDC token endpoint | GitHub Actions |
| `ACTIONS_ID_TOKEN_REQUEST_TOKEN` | OIDC request bearer token | GitHub Actions |
| `GITLAB_CI` | GitLab CI detection | GitLab CI |
| `TF_BUILD` | Azure Pipelines detection | Azure Pipelines |
| `CI` | Generic CI detection | Any CI |

---

## 39. Vault Authentication Patterns

### AWS KMS — IAM role (recommended)

**Bash/Linux/macOS:**
```bash
# On EC2/Lambda/ECS — IAM role is auto-detected, no env vars needed
sigil sign release.tar.gz --vault aws --vault-key alias/my-signing-key

# Required: only the region
export AWS_REGION="us-east-1"
```

**PowerShell/Windows:**
```powershell
# On EC2/Lambda/ECS — IAM role is auto-detected, no env vars needed
sigil sign release.tar.gz --vault aws --vault-key alias/my-signing-key

# Required: only the region
$env:AWS_REGION = "us-east-1"
```

**Minimum IAM policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["kms:GetPublicKey", "kms:Sign"],
    "Resource": "arn:aws:kms:*:ACCOUNT:key/KEY_ID"
  }]
}
```

### AWS KMS — GitHub Actions with OIDC federation

```yaml
permissions:
  id-token: write
steps:
  - uses: aws-actions/configure-aws-credentials@v4
    with:
      role-to-assume: arn:aws:iam::123456789012:role/sigil-signer
      aws-region: us-east-1
  - run: sigil sign release.tar.gz --vault aws --vault-key alias/release-key
```

### Azure Key Vault — Managed Identity (recommended)

**Bash/Linux/macOS:**
```bash
# On Azure VMs, App Service, AKS — Managed Identity is auto-detected
export AZURE_KEY_VAULT_URL="https://myvault.vault.azure.net/"
sigil sign release.tar.gz --vault azure --vault-key my-signing-key
```

**PowerShell/Windows:**
```powershell
# On Azure VMs, App Service, AKS — Managed Identity is auto-detected
$env:AZURE_KEY_VAULT_URL = "https://myvault.vault.azure.net/"
sigil sign release.tar.gz --vault azure --vault-key my-signing-key
```

### Azure Key Vault — Service Principal (CI/CD)

**Bash/Linux/macOS:**
```bash
export AZURE_KEY_VAULT_URL="https://myvault.vault.azure.net/"
export AZURE_TENANT_ID="your-tenant-id"
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-client-secret"
sigil sign release.tar.gz --vault azure --vault-key my-signing-key
```

**PowerShell/Windows:**
```powershell
$env:AZURE_KEY_VAULT_URL = "https://myvault.vault.azure.net/"
$env:AZURE_TENANT_ID = "your-tenant-id"
$env:AZURE_CLIENT_ID = "your-client-id"
$env:AZURE_CLIENT_SECRET = "your-client-secret"
sigil sign release.tar.gz --vault azure --vault-key my-signing-key
```

### Azure Key Vault — GitHub Actions with Workload Identity Federation

```yaml
permissions:
  id-token: write
steps:
  - uses: azure/login@v2
    with:
      client-id: ${{ secrets.AZURE_CLIENT_ID }}
      tenant-id: ${{ secrets.AZURE_TENANT_ID }}
      subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
  - run: |
      export AZURE_KEY_VAULT_URL="https://myvault.vault.azure.net/"
      sigil sign release.tar.gz --vault azure --vault-key my-signing-key
```

### Google Cloud KMS — Service Account (recommended)

**Bash/Linux/macOS:**
```bash
# On GCE/Cloud Run/GKE — service account is auto-detected
sigil sign release.tar.gz --vault gcp \
  --vault-key "projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key/cryptoKeyVersions/1"
```

**PowerShell/Windows:**
```powershell
# On GCE/Cloud Run/GKE — service account is auto-detected
sigil sign release.tar.gz --vault gcp `
  --vault-key "projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key/cryptoKeyVersions/1"
```

### Google Cloud KMS — with credentials file

**Bash/Linux/macOS:**
```bash
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account.json"
sigil sign release.tar.gz --vault gcp \
  --vault-key "projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key/cryptoKeyVersions/1"
```

**PowerShell/Windows:**
```powershell
$env:GOOGLE_APPLICATION_CREDENTIALS = "C:\path\to\service-account.json"
sigil sign release.tar.gz --vault gcp `
  --vault-key "projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key/cryptoKeyVersions/1"
```

### Google Cloud KMS — GitHub Actions with Workload Identity Federation

```yaml
permissions:
  id-token: write
steps:
  - uses: google-github-actions/auth@v2
    with:
      workload_identity_provider: projects/123/locations/global/workloadIdentityPools/pool/providers/github
      service_account: signer@my-project.iam.gserviceaccount.com
  - run: |
      sigil sign release.tar.gz --vault gcp \
        --vault-key "projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key/cryptoKeyVersions/1"
```

### HashiCorp Vault — Token auth (development)

**Bash/Linux/macOS:**
```bash
export VAULT_ADDR="https://vault.example.com:8200"
export VAULT_TOKEN="hvs.your-token-here"
sigil sign release.tar.gz --vault hashicorp --vault-key transit/my-key
```

**PowerShell/Windows:**
```powershell
$env:VAULT_ADDR = "https://vault.example.com:8200"
$env:VAULT_TOKEN = "hvs.your-token-here"
sigil sign release.tar.gz --vault hashicorp --vault-key transit/my-key
```

### HashiCorp Vault — AppRole (CI/CD, recommended)

**Bash/Linux/macOS:**
```bash
export VAULT_ADDR="https://vault.example.com:8200"
export VAULT_ROLE_ID="your-role-id"
export VAULT_SECRET_ID="your-secret-id"  # Short-lived, rotated per job
sigil sign release.tar.gz --vault hashicorp --vault-key transit/release-key
```

**PowerShell/Windows:**
```powershell
$env:VAULT_ADDR = "https://vault.example.com:8200"
$env:VAULT_ROLE_ID = "your-role-id"
$env:VAULT_SECRET_ID = "your-secret-id"  # Short-lived, rotated per job
sigil sign release.tar.gz --vault hashicorp --vault-key transit/release-key
```

**Vault policy (minimum):**
```hcl
path "transit/sign/release-key" {
  capabilities = ["update"]
}
path "transit/keys/release-key" {
  capabilities = ["read"]
}
```

### HashiCorp Vault — Token file (developer workstation)

**Bash/Linux/macOS:**
```bash
# Login to vault (persists token to ~/.vault-token)
vault login -method=ldap username=jdoe

# Sigil auto-reads ~/.vault-token
export VAULT_ADDR="https://vault.example.com:8200"
sigil sign release.tar.gz --vault hashicorp --vault-key transit/my-key
```

**PowerShell/Windows:**
```powershell
# Login to vault (persists token to ~/.vault-token)
vault login -method=ldap username=jdoe

# Sigil auto-reads ~/.vault-token
$env:VAULT_ADDR = "https://vault.example.com:8200"
sigil sign release.tar.gz --vault hashicorp --vault-key transit/my-key
```

### HashiCorp Vault — with namespace (enterprise)

**Bash/Linux/macOS:**
```bash
export VAULT_ADDR="https://vault.example.com:8200"
export VAULT_TOKEN="hvs.your-token"
export VAULT_NAMESPACE="engineering/frontend"
export VAULT_MOUNT_PATH="signing"  # Custom mount point
sigil sign release.tar.gz --vault hashicorp --vault-key my-key
```

**PowerShell/Windows:**
```powershell
$env:VAULT_ADDR = "https://vault.example.com:8200"
$env:VAULT_TOKEN = "hvs.your-token"
$env:VAULT_NAMESPACE = "engineering/frontend"
$env:VAULT_MOUNT_PATH = "signing"  # Custom mount point
sigil sign release.tar.gz --vault hashicorp --vault-key my-key
```

---

## 40. Hardware Token Security (PKCS#11)

### Basic setup with YubiKey

**Bash/Linux/macOS:**
```bash
export PKCS11_LIBRARY="/usr/lib/libykcs11.so"
export PKCS11_PIN="123456"  # Set PIN via env var, not CLI
sigil sign release.tar.gz --vault pkcs11 --vault-key "my-signing-key"
```

**PowerShell/Windows:**
```powershell
$env:PKCS11_LIBRARY = "C:\Program Files\Yubico\YubiKey PIV Tool\bin\libykcs11.dll"
$env:PKCS11_PIN = "123456"  # Set PIN via env var, not CLI
sigil sign release.tar.gz --vault pkcs11 --vault-key "my-signing-key"
```

### Setup with SoftHSM (testing)

**Bash/Linux/macOS:**
```bash
# Initialize token
softhsm2-util --init-token --slot 0 --label "test-token" --pin 1234 --so-pin 5678

export PKCS11_LIBRARY="/usr/lib/softhsm/libsofthsm2.so"
export PKCS11_PIN="1234"
sigil sign release.tar.gz --vault pkcs11 --vault-key "pkcs11:token=test-token;object=my-key"
```

**PowerShell/Windows:**
```powershell
# Initialize token
softhsm2-util --init-token --slot 0 --label "test-token" --pin 1234 --so-pin 5678

$env:PKCS11_LIBRARY = "C:\SoftHSM2\lib\softhsm2.dll"
$env:PKCS11_PIN = "1234"
sigil sign release.tar.gz --vault pkcs11 --vault-key "pkcs11:token=test-token;object=my-key"
```

### PKCS#11 URI with full parameters

**Bash/Linux/macOS:**
```bash
sigil sign release.tar.gz --vault pkcs11 \
  --vault-key "pkcs11:token=MyHSM;object=release-key?module-path=/usr/lib/libhsm.so"
# PIN from PKCS11_PIN env var — never in the URI
```

**PowerShell/Windows:**
```powershell
sigil sign release.tar.gz --vault pkcs11 `
  --vault-key "pkcs11:token=MyHSM;object=release-key?module-path=C:\Program Files\HSM\libhsm.dll"
# PIN from PKCS11_PIN env var — never in the URI
```

### Security best practices for hardware tokens

- **Never put PINs in PKCS#11 URIs** — they may appear in logs
- **Use `PKCS11_PIN` env var** or let the token prompt interactively
- **Private keys never leave the hardware** — only signatures are returned
- **Track PIN attempts** — hardware tokens lock after repeated failures
- **Use dedicated signing tokens** — don't share with authentication

---

## 41. OCI Registry Authentication

### Environment variables (CI/CD)

**Bash/Linux/macOS:**
```bash
export SIGIL_REGISTRY_USERNAME="my-robot-account"
export SIGIL_REGISTRY_PASSWORD="my-access-token"
sigil sign-image ghcr.io/acme/myapp:v1.0 --key mykey.pem
```

**PowerShell/Windows:**
```powershell
$env:SIGIL_REGISTRY_USERNAME = "my-robot-account"
$env:SIGIL_REGISTRY_PASSWORD = "my-access-token"
sigil sign-image ghcr.io/acme/myapp:v1.0 --key mykey.pem
```

### Docker credential helpers (recommended)

Sigil reads `~/.docker/config.json` and uses configured credential helpers automatically:

```json
{
  "credHelpers": {
    "ghcr.io": "gh",
    "*.dkr.ecr.*.amazonaws.com": "ecr-login"
  },
  "credsStore": "desktop"
}
```

```bash
# Just sign — credentials resolved from Docker config
sigil sign-image ghcr.io/acme/myapp:v1.0 --key mykey.pem
```

### GitHub Actions with GHCR

```yaml
steps:
  - uses: docker/login-action@v3
    with:
      registry: ghcr.io
      username: ${{ github.actor }}
      password: ${{ secrets.GITHUB_TOKEN }}
  - run: sigil sign-image ghcr.io/${{ github.repository }}:${{ github.sha }} --keyless
```

---

## 42. Log Server Authentication

### Start a log server with API key

**Bash/Linux/macOS:**
```bash
export SIGIL_API_KEY="your-secret-api-key"
sigil-logserver --port 8443 --cert server.pfx --key signing-key.pfx
```

**PowerShell/Windows:**
```powershell
$env:SIGIL_API_KEY = "your-secret-api-key"
sigil-logserver --port 8443 --cert server.pfx --key signing-key.pfx
```

### Submit to log server

**Bash/Linux/macOS:**
```bash
sigil sign release.tar.gz --key mykey.pem \
  --log-url https://log.example.com \
  --log-api-key "your-secret-api-key"
```

**PowerShell/Windows:**
```powershell
sigil sign release.tar.gz --key mykey.pem `
  --log-url https://log.example.com `
  --log-api-key "your-secret-api-key"
```

### Log server with mTLS (highest security)

```bash
# Server: require client certificates
sigil-logserver --port 8443 --cert server.pfx --key signing-key.pfx --mtls-ca ca-cert.pem

# Client: presents certificate automatically via HTTPS client cert
```

### Log server secrets via environment

**Bash/Linux/macOS:**
```bash
# Server-side
export SIGIL_API_KEY="your-secret-api-key"
export SIGIL_KEY_PASSWORD="signing-key-passphrase"
export SIGIL_CERT_PASSWORD="cert-passphrase"
sigil-logserver --port 8443 --cert-pfx server.pfx --key-pfx signing-key.pfx
```

**PowerShell/Windows:**
```powershell
# Server-side
$env:SIGIL_API_KEY = "your-secret-api-key"
$env:SIGIL_KEY_PASSWORD = "signing-key-passphrase"
$env:SIGIL_CERT_PASSWORD = "cert-passphrase"
sigil-logserver --port 8443 --cert-pfx server.pfx --key-pfx signing-key.pfx
```

---

## 43. Security Best Practices Summary

### Do

- Use **environment variables** or **mounted secret files** for passphrases in CI/CD
- Use **Managed Identity** or **Workload Identity Federation** for cloud vault access
- Use **AppRole with short-lived secrets** for HashiCorp Vault in CI/CD
- Use **PKCS#11 env var** (`PKCS11_PIN`) instead of URI pin-value
- Use **Windows Credential Manager** on developer workstations
- Use **RFC 3161 timestamps** — they protect signatures from key expiry and revocation
- Use **policy enforcement** to codify signing requirements
- Use **anomaly detection** to catch unexpected signing patterns
- Use **keyless/OIDC signing** in CI/CD to eliminate key management entirely

### Don't

- Don't pass `--passphrase` on the command line in production (visible in `ps aux`)
- Don't embed `VAULT_TOKEN` or `AWS_SECRET_ACCESS_KEY` in CI/CD config files
- Don't store PINs in PKCS#11 URIs (they appear in logs and process listings)
- Don't use long-lived tokens for vault authentication in CI/CD
- Don't store passphrase files in version control
- Don't skip timestamping for release signatures
- Don't rely on ephemeral keys for production releases (no identity for trust evaluation)

---

## Algorithm Reference

| Algorithm | Flag | Key Size | Signature Size | Use Case |
|-----------|------|----------|---------------|----------|
| ECDSA P-256 | `ecdsa-p256` | 256-bit | 64 bytes | Default, widely supported |
| ECDSA P-384 | `ecdsa-p384` | 384-bit | 96 bytes | Higher security margin |
| ECDSA P-521 | `ecdsa-p521` | 521-bit | 132 bytes | Maximum ECDSA security |
| RSA-PSS | `rsa-pss-sha256` | 2048-bit | 256 bytes | Legacy compatibility |
| ML-DSA-65 | `ml-dsa-65` | ~1952 bytes | ~3309 bytes | Post-quantum (FIPS 204) |
| Ed25519 | `ed25519` | 32 bytes | 64 bytes | Fast, compact (via BouncyCastle) |
| Ed448 | `ed448` | 57 bytes | 114 bytes | Higher security EdDSA (via BouncyCastle) |

---

## Signature Envelope Format

Every `.sig.json` file follows this structure:

```json
{
  "version": "1.0",
  "subject": {
    "name": "release.tar.gz",
    "digest": {
      "sha256": "abc123..."
    }
  },
  "signatures": [
    {
      "keyId": "sha256:fingerprint...",
      "algorithm": "ecdsa-p256",
      "publicKey": "BASE64_SPKI...",
      "value": "BASE64_SIGNATURE...",
      "timestamp": "2026-02-12T10:30:00Z",
      "label": "ci-build",
      "timestampToken": "BASE64_RFC3161_TOKEN..."
    }
  ]
}
```

Public keys are embedded — no key server or import step needed for verification.
