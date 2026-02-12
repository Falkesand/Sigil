using System.Globalization;
using Sigil.Crypto;
using Sigil.Keyless;
using Sigil.Keys;
using Sigil.Signing;
using Sigil.Timestamping;
using Sigil.Trust;

namespace Sigil.Core.Tests.Trust;

public class TrustEvaluatorTimeTravelTests : IDisposable
{
    private readonly ISigner _signer;
    private readonly KeyFingerprint _fingerprint;
    private readonly ISigner _endorserSigner;
    private readonly KeyFingerprint _endorserFingerprint;

    public TrustEvaluatorTimeTravelTests()
    {
        _signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        _fingerprint = KeyFingerprint.Compute(_signer.PublicKey);
        _endorserSigner = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        _endorserFingerprint = KeyFingerprint.Compute(_endorserSigner.PublicKey);
    }

    public void Dispose()
    {
        _signer.Dispose();
        _endorserSigner.Dispose();
    }

    [Fact]
    public void Revoked_key_evaluated_before_revocation_date_is_trusted()
    {
        var bundle = CreateBundleWithKey(_fingerprint.Value, "Revocable Key");
        bundle.Revocations.Add(new RevocationEntry
        {
            Fingerprint = _fingerprint.Value,
            RevokedAt = "2026-06-01T00:00:00Z",
            Reason = "Compromised"
        });
        var verification = CreateVerificationResult(valid: true);

        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz",
            evaluationTime: ParseDate("2026-01-01T00:00:00Z"));

        Assert.Single(result.Signatures);
        Assert.Equal(TrustDecision.Trusted, result.Signatures[0].Decision);
    }

    [Fact]
    public void Revoked_key_evaluated_after_revocation_date_is_revoked()
    {
        var bundle = CreateBundleWithKey(_fingerprint.Value, "Revocable Key");
        bundle.Revocations.Add(new RevocationEntry
        {
            Fingerprint = _fingerprint.Value,
            RevokedAt = "2026-06-01T00:00:00Z",
            Reason = "Compromised"
        });
        var verification = CreateVerificationResult(valid: true);

        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz",
            evaluationTime: ParseDate("2026-07-01T00:00:00Z"));

        Assert.Single(result.Signatures);
        Assert.Equal(TrustDecision.Revoked, result.Signatures[0].Decision);
    }

    [Fact]
    public void Revoked_key_evaluated_at_exact_revocation_date_is_revoked()
    {
        var bundle = CreateBundleWithKey(_fingerprint.Value, "Revocable Key");
        bundle.Revocations.Add(new RevocationEntry
        {
            Fingerprint = _fingerprint.Value,
            RevokedAt = "2026-06-01T00:00:00Z"
        });
        var verification = CreateVerificationResult(valid: true);

        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz",
            evaluationTime: ParseDate("2026-06-01T00:00:00Z"));

        Assert.Single(result.Signatures);
        Assert.Equal(TrustDecision.Revoked, result.Signatures[0].Decision);
    }

    [Fact]
    public void Revoked_key_with_unparseable_revokedAt_is_revoked()
    {
        var bundle = CreateBundleWithKey(_fingerprint.Value, "Revocable Key");
        bundle.Revocations.Add(new RevocationEntry
        {
            Fingerprint = _fingerprint.Value,
            RevokedAt = "not-a-date"
        });
        var verification = CreateVerificationResult(valid: true);

        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz",
            evaluationTime: ParseDate("2026-01-01T00:00:00Z"));

        Assert.Single(result.Signatures);
        Assert.Equal(TrustDecision.Revoked, result.Signatures[0].Decision);
    }

    [Fact]
    public void Expired_key_evaluated_before_expiry_is_trusted()
    {
        var bundle = CreateBundleWithKey(_fingerprint.Value, "Expiring Key",
            notAfter: "2026-06-01T00:00:00Z");
        var verification = CreateVerificationResult(valid: true);

        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz",
            evaluationTime: ParseDate("2026-01-01T00:00:00Z"));

        Assert.Single(result.Signatures);
        Assert.Equal(TrustDecision.Trusted, result.Signatures[0].Decision);
    }

    [Fact]
    public void Expired_key_evaluated_after_expiry_is_expired()
    {
        var bundle = CreateBundleWithKey(_fingerprint.Value, "Expiring Key",
            notAfter: "2026-06-01T00:00:00Z");
        var verification = CreateVerificationResult(valid: true);

        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz",
            evaluationTime: ParseDate("2026-07-01T00:00:00Z"));

        Assert.Single(result.Signatures);
        Assert.Equal(TrustDecision.Expired, result.Signatures[0].Decision);
    }

    [Fact]
    public void Expired_key_with_timestamp_before_expiry_evaluated_after_is_trusted()
    {
        var bundle = CreateBundleWithKey(_fingerprint.Value, "Expiring Key",
            notAfter: "2026-06-01T00:00:00Z");
        var timestamp = new TimestampVerificationInfo
        {
            Timestamp = ParseDate("2026-03-01T00:00:00Z"),
            IsValid = true
        };
        var verification = CreateVerificationResult(valid: true, timestampInfo: timestamp);

        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz",
            evaluationTime: ParseDate("2027-01-01T00:00:00Z"));

        Assert.Single(result.Signatures);
        Assert.Equal(TrustDecision.Trusted, result.Signatures[0].Decision);
    }

    [Fact]
    public void Endorsement_expired_at_evaluation_time_is_untrusted()
    {
        var bundle = new TrustBundle
        {
            Metadata = new BundleMetadata { Name = "test", Created = "2026-02-08T12:00:00Z" },
            Keys = [new TrustedKeyEntry { Fingerprint = _endorserFingerprint.Value, DisplayName = "Endorser" }],
            Endorsements =
            [
                new Endorsement
                {
                    Endorser = _endorserFingerprint.Value,
                    Endorsed = _fingerprint.Value,
                    Statement = "I vouch for this key",
                    Timestamp = "2026-01-01T00:00:00Z",
                    NotAfter = "2026-06-01T00:00:00Z"
                }
            ]
        };
        var verification = CreateVerificationResult(valid: true);

        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz",
            evaluationTime: ParseDate("2027-01-01T00:00:00Z"));

        Assert.Single(result.Signatures);
        Assert.Equal(TrustDecision.Untrusted, result.Signatures[0].Decision);
    }

    [Fact]
    public void Endorsement_not_expired_at_evaluation_time_is_trusted_via_endorsement()
    {
        var bundle = new TrustBundle
        {
            Metadata = new BundleMetadata { Name = "test", Created = "2026-02-08T12:00:00Z" },
            Keys = [new TrustedKeyEntry { Fingerprint = _endorserFingerprint.Value, DisplayName = "Endorser" }],
            Endorsements =
            [
                new Endorsement
                {
                    Endorser = _endorserFingerprint.Value,
                    Endorsed = _fingerprint.Value,
                    Statement = "I vouch for this key",
                    Timestamp = "2026-01-01T00:00:00Z",
                    NotAfter = "2026-06-01T00:00:00Z"
                }
            ]
        };
        var verification = CreateVerificationResult(valid: true);

        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz",
            evaluationTime: ParseDate("2026-01-01T00:00:00Z"));

        Assert.Single(result.Signatures);
        Assert.Equal(TrustDecision.TrustedViaEndorsement, result.Signatures[0].Decision);
    }

    [Fact]
    public void Oidc_identity_expired_at_evaluation_time_is_untrusted()
    {
        // Timestamp must be after identity expiry so the timestamp override doesn't apply
        var timestamp = new TimestampVerificationInfo
        {
            Timestamp = ParseDate("2026-09-01T00:00:00Z"),
            IsValid = true
        };
        var verification = CreateVerificationResult(valid: true, timestampInfo: timestamp);
        var bundle = new TrustBundle
        {
            Metadata = new BundleMetadata { Name = "test", Created = "2026-02-08T12:00:00Z" },
            Identities =
            [
                new TrustedIdentity
                {
                    Issuer = "https://accounts.google.com",
                    SubjectPattern = "user@example.com",
                    DisplayName = "Test Identity",
                    NotAfter = "2026-06-01T00:00:00Z"
                }
            ]
        };
        var oidcInfo = new Dictionary<string, OidcVerificationInfo>
        {
            [_fingerprint.Value] = new OidcVerificationInfo
            {
                IsValid = true,
                Issuer = "https://accounts.google.com",
                Identity = "user@example.com"
            }
        };

        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz",
            evaluationTime: ParseDate("2027-01-01T00:00:00Z"),
            oidcInfo: oidcInfo);

        Assert.Single(result.Signatures);
        Assert.Equal(TrustDecision.Untrusted, result.Signatures[0].Decision);
    }

    [Fact]
    public void Oidc_identity_not_expired_at_evaluation_time_is_trusted_via_oidc()
    {
        var timestamp = new TimestampVerificationInfo
        {
            Timestamp = ParseDate("2026-03-01T00:00:00Z"),
            IsValid = true
        };
        var verification = CreateVerificationResult(valid: true, timestampInfo: timestamp);
        var bundle = new TrustBundle
        {
            Metadata = new BundleMetadata { Name = "test", Created = "2026-02-08T12:00:00Z" },
            Identities =
            [
                new TrustedIdentity
                {
                    Issuer = "https://accounts.google.com",
                    SubjectPattern = "user@example.com",
                    DisplayName = "Test Identity",
                    NotAfter = "2026-06-01T00:00:00Z"
                }
            ]
        };
        var oidcInfo = new Dictionary<string, OidcVerificationInfo>
        {
            [_fingerprint.Value] = new OidcVerificationInfo
            {
                IsValid = true,
                Issuer = "https://accounts.google.com",
                Identity = "user@example.com"
            }
        };

        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz",
            evaluationTime: ParseDate("2026-01-01T00:00:00Z"),
            oidcInfo: oidcInfo);

        Assert.Single(result.Signatures);
        Assert.Equal(TrustDecision.TrustedViaOidc, result.Signatures[0].Decision);
    }

    [Fact]
    public void Revoked_and_expired_key_evaluated_before_revocation_is_trusted()
    {
        var bundle = CreateBundleWithKey(_fingerprint.Value, "Dual Key",
            notAfter: "2027-01-01T00:00:00Z");
        bundle.Revocations.Add(new RevocationEntry
        {
            Fingerprint = _fingerprint.Value,
            RevokedAt = "2026-06-01T00:00:00Z",
            Reason = "Compromised"
        });
        var verification = CreateVerificationResult(valid: true);

        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz",
            evaluationTime: ParseDate("2026-01-01T00:00:00Z"));

        Assert.Single(result.Signatures);
        Assert.Equal(TrustDecision.Trusted, result.Signatures[0].Decision);
    }

    [Fact]
    public void Revoked_and_expired_key_evaluated_after_both_is_revoked()
    {
        var bundle = CreateBundleWithKey(_fingerprint.Value, "Dual Key",
            notAfter: "2027-01-01T00:00:00Z");
        bundle.Revocations.Add(new RevocationEntry
        {
            Fingerprint = _fingerprint.Value,
            RevokedAt = "2026-06-01T00:00:00Z",
            Reason = "Compromised"
        });
        var verification = CreateVerificationResult(valid: true);

        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz",
            evaluationTime: ParseDate("2028-01-01T00:00:00Z"));

        Assert.Single(result.Signatures);
        Assert.Equal(TrustDecision.Revoked, result.Signatures[0].Decision);
    }

    [Fact]
    public void Evaluation_time_in_future_works_correctly()
    {
        var bundle = CreateBundleWithKey(_fingerprint.Value, "Future Key",
            notAfter: "2030-01-01T00:00:00Z");
        var verification = CreateVerificationResult(valid: true);

        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz",
            evaluationTime: ParseDate("2029-01-01T00:00:00Z"));

        Assert.Single(result.Signatures);
        Assert.Equal(TrustDecision.Trusted, result.Signatures[0].Decision);
    }

    [Fact]
    public void Endorser_revoked_before_evaluation_time_untrusts_endorsed_key()
    {
        var bundle = new TrustBundle
        {
            Metadata = new BundleMetadata { Name = "test", Created = "2026-02-08T12:00:00Z" },
            Keys = [new TrustedKeyEntry { Fingerprint = _endorserFingerprint.Value, DisplayName = "Endorser" }],
            Endorsements =
            [
                new Endorsement
                {
                    Endorser = _endorserFingerprint.Value,
                    Endorsed = _fingerprint.Value,
                    Statement = "I vouch for this key",
                    Timestamp = "2026-01-01T00:00:00Z"
                }
            ],
            Revocations =
            [
                new RevocationEntry
                {
                    Fingerprint = _endorserFingerprint.Value,
                    RevokedAt = "2026-06-01T00:00:00Z",
                    Reason = "Endorser compromised"
                }
            ]
        };
        var verification = CreateVerificationResult(valid: true);

        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz",
            evaluationTime: ParseDate("2027-01-01T00:00:00Z"));

        Assert.Single(result.Signatures);
        Assert.Equal(TrustDecision.Untrusted, result.Signatures[0].Decision);
    }

    private VerificationResult CreateVerificationResult(bool valid, string? algorithm = "ecdsa-p256",
        TimestampVerificationInfo? timestampInfo = null)
        => new()
        {
            ArtifactDigestMatch = true,
            Signatures =
            [
                new SignatureVerificationResult
                {
                    KeyId = _fingerprint.Value,
                    IsValid = valid,
                    Algorithm = algorithm,
                    TimestampInfo = timestampInfo
                }
            ]
        };

    private static TrustBundle CreateBundleWithKey(string fingerprint, string displayName,
        string? notAfter = null) => new()
    {
        Metadata = new BundleMetadata { Name = "test", Created = "2026-02-08T12:00:00Z" },
        Keys = [new TrustedKeyEntry { Fingerprint = fingerprint, DisplayName = displayName, NotAfter = notAfter }]
    };

    private static DateTimeOffset ParseDate(string date)
        => DateTimeOffset.Parse(date, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal);
}
