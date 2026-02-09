using Sigil.Crypto;
using Sigil.Keys;
using Sigil.Signing;
using Sigil.Trust;

namespace Sigil.Core.Tests.Trust;

public class TrustEvaluatorRevocationTests : IDisposable
{
    private readonly ISigner _signer;
    private readonly KeyFingerprint _fingerprint;

    public TrustEvaluatorRevocationTests()
    {
        _signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        _fingerprint = KeyFingerprint.Compute(_signer.PublicKey);
    }

    public void Dispose()
    {
        _signer.Dispose();
    }

    [Fact]
    public void Revoked_when_key_in_revocation_list()
    {
        var bundle = new TrustBundle
        {
            Metadata = new BundleMetadata { Name = "test", Created = "2026-02-09T12:00:00Z" },
            Keys = [new TrustedKeyEntry { Fingerprint = _fingerprint.Value, DisplayName = "Revoked Key" }],
            Revocations =
            [
                new RevocationEntry
                {
                    Fingerprint = _fingerprint.Value,
                    RevokedAt = "2026-02-09T10:00:00Z",
                    Reason = "Key compromised"
                }
            ]
        };

        var verification = CreateVerification(valid: true);
        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz");

        Assert.Single(result.Signatures);
        Assert.Equal(TrustDecision.Revoked, result.Signatures[0].Decision);
        Assert.Contains("revoked", result.Signatures[0].Reason, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Key compromised", result.Signatures[0].Reason);
    }

    [Fact]
    public void Revoked_overrides_trusted_even_with_valid_timestamp()
    {
        var bundle = new TrustBundle
        {
            Metadata = new BundleMetadata { Name = "test", Created = "2026-02-09T12:00:00Z" },
            Keys = [new TrustedKeyEntry { Fingerprint = _fingerprint.Value }],
            Revocations =
            [
                new RevocationEntry
                {
                    Fingerprint = _fingerprint.Value,
                    RevokedAt = "2026-02-09T10:00:00Z",
                    Reason = "Compromised"
                }
            ]
        };

        var verification = CreateVerification(valid: true);
        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz");

        Assert.Equal(TrustDecision.Revoked, result.Signatures[0].Decision);
    }

    [Fact]
    public void Revoked_without_reason_shows_default_message()
    {
        var bundle = new TrustBundle
        {
            Metadata = new BundleMetadata { Name = "test", Created = "2026-02-09T12:00:00Z" },
            Keys = [new TrustedKeyEntry { Fingerprint = _fingerprint.Value }],
            Revocations =
            [
                new RevocationEntry
                {
                    Fingerprint = _fingerprint.Value,
                    RevokedAt = "2026-02-09T10:00:00Z"
                }
            ]
        };

        var verification = CreateVerification(valid: true);
        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz");

        Assert.Equal(TrustDecision.Revoked, result.Signatures[0].Decision);
        Assert.Contains("2026-02-09", result.Signatures[0].Reason);
    }

    [Fact]
    public void Not_revoked_when_different_key_is_revoked()
    {
        var bundle = new TrustBundle
        {
            Metadata = new BundleMetadata { Name = "test", Created = "2026-02-09T12:00:00Z" },
            Keys = [new TrustedKeyEntry { Fingerprint = _fingerprint.Value }],
            Revocations =
            [
                new RevocationEntry
                {
                    Fingerprint = "sha256:" + new string('f', 64),
                    RevokedAt = "2026-02-09T10:00:00Z",
                    Reason = "Other key compromised"
                }
            ]
        };

        var verification = CreateVerification(valid: true);
        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz");

        Assert.Equal(TrustDecision.Trusted, result.Signatures[0].Decision);
    }

    [Fact]
    public void Revoked_endorser_blocks_endorsement_trust()
    {
        using var endorsedSigner = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var endorsedFp = KeyFingerprint.Compute(endorsedSigner.PublicKey);

        var bundle = new TrustBundle
        {
            Metadata = new BundleMetadata { Name = "test", Created = "2026-02-09T12:00:00Z" },
            Keys = [new TrustedKeyEntry { Fingerprint = _fingerprint.Value, DisplayName = "Endorser" }],
            Endorsements =
            [
                new Endorsement
                {
                    Endorser = _fingerprint.Value,
                    Endorsed = endorsedFp.Value,
                    Timestamp = "2026-02-09T08:00:00Z"
                }
            ],
            Revocations =
            [
                new RevocationEntry
                {
                    Fingerprint = _fingerprint.Value,
                    RevokedAt = "2026-02-09T10:00:00Z",
                    Reason = "Endorser key compromised"
                }
            ]
        };

        var verification = new VerificationResult
        {
            ArtifactDigestMatch = true,
            Signatures =
            [
                new SignatureVerificationResult
                {
                    KeyId = endorsedFp.Value,
                    IsValid = true,
                    Algorithm = "ecdsa-p256",
                    Label = null
                }
            ]
        };

        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz");

        // Endorsed key should be untrusted because endorser is revoked
        Assert.Equal(TrustDecision.Untrusted, result.Signatures[0].Decision);
    }

    [Fact]
    public void Revoked_endorsed_key_blocks_endorsement_trust()
    {
        using var endorsedSigner = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var endorsedFp = KeyFingerprint.Compute(endorsedSigner.PublicKey);

        var bundle = new TrustBundle
        {
            Metadata = new BundleMetadata { Name = "test", Created = "2026-02-09T12:00:00Z" },
            Keys = [new TrustedKeyEntry { Fingerprint = _fingerprint.Value, DisplayName = "Endorser" }],
            Endorsements =
            [
                new Endorsement
                {
                    Endorser = _fingerprint.Value,
                    Endorsed = endorsedFp.Value,
                    Timestamp = "2026-02-09T08:00:00Z"
                }
            ],
            Revocations =
            [
                new RevocationEntry
                {
                    Fingerprint = endorsedFp.Value,
                    RevokedAt = "2026-02-09T10:00:00Z",
                    Reason = "Endorsed key compromised"
                }
            ]
        };

        var verification = new VerificationResult
        {
            ArtifactDigestMatch = true,
            Signatures =
            [
                new SignatureVerificationResult
                {
                    KeyId = endorsedFp.Value,
                    IsValid = true,
                    Algorithm = "ecdsa-p256",
                    Label = null
                }
            ]
        };

        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz");

        Assert.Equal(TrustDecision.Revoked, result.Signatures[0].Decision);
        Assert.Contains("Endorsed key compromised", result.Signatures[0].Reason);
    }

    [Fact]
    public void Crypto_failure_still_trumps_revocation()
    {
        var bundle = new TrustBundle
        {
            Metadata = new BundleMetadata { Name = "test", Created = "2026-02-09T12:00:00Z" },
            Keys = [new TrustedKeyEntry { Fingerprint = _fingerprint.Value }],
            Revocations =
            [
                new RevocationEntry
                {
                    Fingerprint = _fingerprint.Value,
                    RevokedAt = "2026-02-09T10:00:00Z"
                }
            ]
        };

        var verification = CreateVerification(valid: false);
        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz");

        // Crypto failure still comes first
        Assert.Equal(TrustDecision.Untrusted, result.Signatures[0].Decision);
        Assert.Contains("Cryptographic", result.Signatures[0].Reason);
    }

    [Fact]
    public void AnyTrusted_false_when_all_revoked()
    {
        var bundle = new TrustBundle
        {
            Metadata = new BundleMetadata { Name = "test", Created = "2026-02-09T12:00:00Z" },
            Keys = [new TrustedKeyEntry { Fingerprint = _fingerprint.Value }],
            Revocations =
            [
                new RevocationEntry
                {
                    Fingerprint = _fingerprint.Value,
                    RevokedAt = "2026-02-09T10:00:00Z"
                }
            ]
        };

        var verification = CreateVerification(valid: true);
        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz");

        Assert.False(result.AnyTrusted);
        Assert.False(result.AllTrusted);
    }

    [Fact]
    public void Empty_revocations_list_does_not_affect_trust()
    {
        var bundle = new TrustBundle
        {
            Metadata = new BundleMetadata { Name = "test", Created = "2026-02-09T12:00:00Z" },
            Keys = [new TrustedKeyEntry { Fingerprint = _fingerprint.Value }],
            Revocations = []
        };

        var verification = CreateVerification(valid: true);
        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz");

        Assert.Equal(TrustDecision.Trusted, result.Signatures[0].Decision);
    }

    private VerificationResult CreateVerification(bool valid) => new()
    {
        ArtifactDigestMatch = true,
        Signatures =
        [
            new SignatureVerificationResult
            {
                KeyId = _fingerprint.Value,
                IsValid = valid,
                Algorithm = "ecdsa-p256",
                Label = null
            }
        ]
    };
}
