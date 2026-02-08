using Sigil.Crypto;
using Sigil.Keys;
using Sigil.Signing;
using Sigil.Timestamping;
using Sigil.Trust;

namespace Sigil.Core.Tests.Trust;

public class TrustEvaluatorTimestampTests : IDisposable
{
    private readonly ISigner _signer;
    private readonly KeyFingerprint _fingerprint;

    public TrustEvaluatorTimestampTests()
    {
        _signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        _fingerprint = KeyFingerprint.Compute(_signer.PublicKey);
    }

    public void Dispose()
    {
        _signer.Dispose();
    }

    [Fact]
    public void ExpiredKey_ValidTimestampBeforeExpiry_Trusted()
    {
        var bundle = CreateBundleWithKey(_fingerprint.Value, "Test Key",
            notAfter: "2026-01-01T00:00:00Z");
        var verification = CreateVerificationResult(valid: true,
            timestampInfo: new TimestampVerificationInfo
            {
                Timestamp = new DateTimeOffset(2025, 12, 15, 0, 0, 0, TimeSpan.Zero),
                IsValid = true
            });

        // Evaluate at a time after the key expired
        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz",
            evaluationTime: new DateTimeOffset(2026, 6, 1, 0, 0, 0, TimeSpan.Zero));

        Assert.Single(result.Signatures);
        Assert.Equal(TrustDecision.Trusted, result.Signatures[0].Decision);
    }

    [Fact]
    public void ExpiredKey_ValidTimestampAfterExpiry_Expired()
    {
        var bundle = CreateBundleWithKey(_fingerprint.Value, "Test Key",
            notAfter: "2026-01-01T00:00:00Z");
        var verification = CreateVerificationResult(valid: true,
            timestampInfo: new TimestampVerificationInfo
            {
                Timestamp = new DateTimeOffset(2026, 3, 1, 0, 0, 0, TimeSpan.Zero),
                IsValid = true
            });

        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz",
            evaluationTime: new DateTimeOffset(2026, 6, 1, 0, 0, 0, TimeSpan.Zero));

        Assert.Single(result.Signatures);
        Assert.Equal(TrustDecision.Expired, result.Signatures[0].Decision);
    }

    [Fact]
    public void ExpiredKey_NoTimestamp_Expired()
    {
        var bundle = CreateBundleWithKey(_fingerprint.Value, "Test Key",
            notAfter: "2026-01-01T00:00:00Z");
        var verification = CreateVerificationResult(valid: true, timestampInfo: null);

        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz",
            evaluationTime: new DateTimeOffset(2026, 6, 1, 0, 0, 0, TimeSpan.Zero));

        Assert.Single(result.Signatures);
        Assert.Equal(TrustDecision.Expired, result.Signatures[0].Decision);
    }

    [Fact]
    public void ExpiredKey_InvalidTimestamp_Expired()
    {
        var bundle = CreateBundleWithKey(_fingerprint.Value, "Test Key",
            notAfter: "2026-01-01T00:00:00Z");
        var verification = CreateVerificationResult(valid: true,
            timestampInfo: new TimestampVerificationInfo
            {
                Timestamp = new DateTimeOffset(2025, 12, 15, 0, 0, 0, TimeSpan.Zero),
                IsValid = false,
                Error = "Invalid token"
            });

        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz",
            evaluationTime: new DateTimeOffset(2026, 6, 1, 0, 0, 0, TimeSpan.Zero));

        Assert.Single(result.Signatures);
        Assert.Equal(TrustDecision.Expired, result.Signatures[0].Decision);
    }

    [Fact]
    public void Endorser_Expired_ValidTimestamp_TrustedViaEndorsement()
    {
        using var endorserSigner = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var endorserFp = KeyFingerprint.Compute(endorserSigner.PublicKey);

        var bundle = new TrustBundle
        {
            Metadata = new BundleMetadata { Name = "test", Created = "2026-02-08T12:00:00Z" },
            Keys =
            [
                new TrustedKeyEntry
                {
                    Fingerprint = endorserFp.Value,
                    DisplayName = "Endorser",
                    NotAfter = "2026-01-01T00:00:00Z" // expired
                }
            ],
            Endorsements =
            [
                new Endorsement
                {
                    Endorser = endorserFp.Value,
                    Endorsed = _fingerprint.Value,
                    Timestamp = "2025-06-01T00:00:00Z",
                    Statement = "Trusted collaborator"
                }
            ]
        };

        var verification = CreateVerificationResult(valid: true,
            timestampInfo: new TimestampVerificationInfo
            {
                Timestamp = new DateTimeOffset(2025, 12, 15, 0, 0, 0, TimeSpan.Zero),
                IsValid = true
            });

        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz",
            evaluationTime: new DateTimeOffset(2026, 6, 1, 0, 0, 0, TimeSpan.Zero));

        Assert.Single(result.Signatures);
        Assert.Equal(TrustDecision.TrustedViaEndorsement, result.Signatures[0].Decision);
    }

    [Fact]
    public void NonExpiredKey_StillTrusted_WithTimestamp()
    {
        var bundle = CreateBundleWithKey(_fingerprint.Value, "Test Key",
            notAfter: "2027-01-01T00:00:00Z");
        var verification = CreateVerificationResult(valid: true,
            timestampInfo: new TimestampVerificationInfo
            {
                Timestamp = new DateTimeOffset(2026, 6, 1, 0, 0, 0, TimeSpan.Zero),
                IsValid = true
            });

        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz",
            evaluationTime: new DateTimeOffset(2026, 6, 1, 0, 0, 0, TimeSpan.Zero));

        Assert.Single(result.Signatures);
        Assert.Equal(TrustDecision.Trusted, result.Signatures[0].Decision);
    }

    private VerificationResult CreateVerificationResult(
        bool valid, TimestampVerificationInfo? timestampInfo = null) =>
        new()
        {
            ArtifactDigestMatch = true,
            Signatures =
            [
                new SignatureVerificationResult
                {
                    KeyId = _fingerprint.Value,
                    IsValid = valid,
                    Algorithm = "ecdsa-p256",
                    TimestampInfo = timestampInfo
                }
            ]
        };

    private static TrustBundle CreateBundleWithKey(string fingerprint, string displayName,
        string? notAfter = null) => new()
    {
        Metadata = new BundleMetadata { Name = "test", Created = "2026-02-08T12:00:00Z" },
        Keys =
        [
            new TrustedKeyEntry
            {
                Fingerprint = fingerprint,
                DisplayName = displayName,
                NotAfter = notAfter
            }
        ]
    };
}
