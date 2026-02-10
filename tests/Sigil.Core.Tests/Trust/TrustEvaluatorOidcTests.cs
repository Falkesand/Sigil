using Sigil.Crypto;
using Sigil.Keyless;
using Sigil.Keys;
using Sigil.Signing;
using Sigil.Timestamping;
using Sigil.Trust;

namespace Sigil.Core.Tests.Trust;

public class TrustEvaluatorOidcTests : IDisposable
{
    private readonly ISigner _signer;
    private readonly KeyFingerprint _fingerprint;

    public TrustEvaluatorOidcTests()
    {
        _signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        _fingerprint = KeyFingerprint.Compute(_signer.PublicKey);
    }

    public void Dispose()
    {
        _signer.Dispose();
    }

    [Fact]
    public void TrustedViaOidc_OnMatchAndTimestamp()
    {
        var bundle = CreateBundleWithIdentity(
            "https://token.actions.githubusercontent.com", "repo:myorg/*", "GitHub CI");
        var verification = CreateVerificationResult(valid: true, withTimestamp: true);
        var oidcInfo = CreateOidcInfo(
            "https://token.actions.githubusercontent.com", "repo:myorg/myrepo");

        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz", oidcInfo: oidcInfo);

        Assert.Single(result.Signatures);
        Assert.Equal(TrustDecision.TrustedViaOidc, result.Signatures[0].Decision);
        Assert.Equal("GitHub CI", result.Signatures[0].DisplayName);
        Assert.Equal("https://token.actions.githubusercontent.com", result.Signatures[0].OidcIssuer);
        Assert.Equal("repo:myorg/myrepo", result.Signatures[0].OidcIdentity);
    }

    [Fact]
    public void Untrusted_NoOidcInfo()
    {
        var bundle = CreateBundleWithIdentity(
            "https://token.actions.githubusercontent.com", "repo:myorg/*");
        var verification = CreateVerificationResult(valid: true, withTimestamp: true);

        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz");

        Assert.Equal(TrustDecision.Untrusted, result.Signatures[0].Decision);
    }

    [Fact]
    public void Untrusted_InvalidOidc()
    {
        var bundle = CreateBundleWithIdentity(
            "https://token.actions.githubusercontent.com", "repo:myorg/*");
        var verification = CreateVerificationResult(valid: true, withTimestamp: true);
        var oidcInfo = new Dictionary<string, OidcVerificationInfo>
        {
            [_fingerprint.Value] = new OidcVerificationInfo
            {
                IsValid = false,
                Error = "Token validation failed"
            }
        };

        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz", oidcInfo: oidcInfo);

        Assert.Equal(TrustDecision.Untrusted, result.Signatures[0].Decision);
    }

    [Fact]
    public void Untrusted_IssuerMismatch()
    {
        var bundle = CreateBundleWithIdentity(
            "https://token.actions.githubusercontent.com", "repo:myorg/*");
        var verification = CreateVerificationResult(valid: true, withTimestamp: true);
        var oidcInfo = CreateOidcInfo(
            "https://different-issuer.example.com", "repo:myorg/myrepo");

        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz", oidcInfo: oidcInfo);

        Assert.Equal(TrustDecision.Untrusted, result.Signatures[0].Decision);
    }

    [Fact]
    public void Untrusted_SubjectMismatch()
    {
        var bundle = CreateBundleWithIdentity(
            "https://token.actions.githubusercontent.com", "repo:myorg/*");
        var verification = CreateVerificationResult(valid: true, withTimestamp: true);
        var oidcInfo = CreateOidcInfo(
            "https://token.actions.githubusercontent.com", "repo:otherorg/repo");

        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz", oidcInfo: oidcInfo);

        Assert.Equal(TrustDecision.Untrusted, result.Signatures[0].Decision);
    }

    [Fact]
    public void Untrusted_NoTimestamp()
    {
        var bundle = CreateBundleWithIdentity(
            "https://token.actions.githubusercontent.com", "repo:myorg/*");
        var verification = CreateVerificationResult(valid: true, withTimestamp: false);
        var oidcInfo = CreateOidcInfo(
            "https://token.actions.githubusercontent.com", "repo:myorg/myrepo");

        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz", oidcInfo: oidcInfo);

        Assert.Equal(TrustDecision.Untrusted, result.Signatures[0].Decision);
        Assert.Contains("timestamp", result.Signatures[0].Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void IdentityExpired_WithTimestampBefore_Trusted()
    {
        var bundle = CreateBundleWithIdentity(
            "https://token.actions.githubusercontent.com", "repo:myorg/*",
            notAfter: "2026-01-01T00:00:00Z");
        var verification = CreateVerificationResult(valid: true,
            timestampInfo: new TimestampVerificationInfo
            {
                Timestamp = new DateTimeOffset(2025, 12, 15, 0, 0, 0, TimeSpan.Zero),
                IsValid = true
            });
        var oidcInfo = CreateOidcInfo(
            "https://token.actions.githubusercontent.com", "repo:myorg/myrepo");

        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz",
            evaluationTime: new DateTimeOffset(2026, 6, 1, 0, 0, 0, TimeSpan.Zero),
            oidcInfo: oidcInfo);

        Assert.Equal(TrustDecision.TrustedViaOidc, result.Signatures[0].Decision);
    }

    [Fact]
    public void IdentityExpired_NoTimestamp_Untrusted()
    {
        var bundle = CreateBundleWithIdentity(
            "https://token.actions.githubusercontent.com", "repo:myorg/*",
            notAfter: "2026-01-01T00:00:00Z");
        var verification = CreateVerificationResult(valid: true, withTimestamp: true);
        var oidcInfo = CreateOidcInfo(
            "https://token.actions.githubusercontent.com", "repo:myorg/myrepo");

        // Evaluate at a time after the identity expired, but timestamp is after expiry too
        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz",
            evaluationTime: new DateTimeOffset(2026, 6, 1, 0, 0, 0, TimeSpan.Zero),
            oidcInfo: oidcInfo);

        // The default timestamp from withTimestamp:true is "now", which is after the NotAfter
        Assert.Equal(TrustDecision.Untrusted, result.Signatures[0].Decision);
    }

    [Fact]
    public void GlobWildcard_Matches()
    {
        var bundle = CreateBundleWithIdentity(
            "https://token.actions.githubusercontent.com", "*");
        var verification = CreateVerificationResult(valid: true, withTimestamp: true);
        var oidcInfo = CreateOidcInfo(
            "https://token.actions.githubusercontent.com", "anything-at-all");

        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz", oidcInfo: oidcInfo);

        Assert.Equal(TrustDecision.TrustedViaOidc, result.Signatures[0].Decision);
    }

    [Fact]
    public void KeyTrust_TakesPrecedence_OverOidc()
    {
        // Bundle has both a direct key entry AND an OIDC identity
        var bundle = new TrustBundle
        {
            Metadata = new BundleMetadata { Name = "test", Created = "2025-01-01T00:00:00Z" },
            Keys =
            [
                new TrustedKeyEntry
                {
                    Fingerprint = _fingerprint.Value,
                    DisplayName = "Direct Key"
                }
            ],
            Identities =
            [
                new TrustedIdentity
                {
                    Issuer = "https://token.actions.githubusercontent.com",
                    SubjectPattern = "*"
                }
            ]
        };
        var verification = CreateVerificationResult(valid: true, withTimestamp: true);
        var oidcInfo = CreateOidcInfo(
            "https://token.actions.githubusercontent.com", "repo:myorg/myrepo");

        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz", oidcInfo: oidcInfo);

        // Direct key trust should take precedence (Rule 3a before 3c)
        Assert.Equal(TrustDecision.Trusted, result.Signatures[0].Decision);
        Assert.Equal("Direct Key", result.Signatures[0].DisplayName);
    }

    [Fact]
    public void AnyTrusted_AllTrusted_IncludeOidc()
    {
        var bundle = CreateBundleWithIdentity(
            "https://token.actions.githubusercontent.com", "repo:myorg/*");
        var verification = CreateVerificationResult(valid: true, withTimestamp: true);
        var oidcInfo = CreateOidcInfo(
            "https://token.actions.githubusercontent.com", "repo:myorg/myrepo");

        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz", oidcInfo: oidcInfo);

        Assert.True(result.AnyTrusted);
        Assert.True(result.AllTrusted);
    }

    [Fact]
    public void BackwardCompat_NullOidcInfo_Works()
    {
        var bundle = CreateBundleWithKey(_fingerprint.Value, "Test Key");
        var verification = CreateVerificationResult(valid: true);

        // Call without OIDC info — should behave exactly as before
        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz");

        Assert.Equal(TrustDecision.Trusted, result.Signatures[0].Decision);
    }

    private VerificationResult CreateVerificationResult(
        bool valid, bool withTimestamp = false,
        TimestampVerificationInfo? timestampInfo = null)
    {
        var tsInfo = timestampInfo ?? (withTimestamp ? new TimestampVerificationInfo
        {
            Timestamp = DateTimeOffset.UtcNow,
            IsValid = true
        } : null);

        return new VerificationResult
        {
            ArtifactDigestMatch = true,
            Signatures =
            [
                new SignatureVerificationResult
                {
                    KeyId = _fingerprint.Value,
                    IsValid = valid,
                    Algorithm = "ecdsa-p256",
                    TimestampInfo = tsInfo
                }
            ]
        };
    }

    private Dictionary<string, OidcVerificationInfo> CreateOidcInfo(string issuer, string identity)
    {
        return new Dictionary<string, OidcVerificationInfo>
        {
            [_fingerprint.Value] = new OidcVerificationInfo
            {
                IsValid = true,
                Issuer = issuer,
                Identity = identity
            }
        };
    }

    private static TrustBundle CreateBundleWithIdentity(
        string issuer, string subjectPattern,
        string? displayName = null, string? notAfter = null)
    {
        return new TrustBundle
        {
            Metadata = new BundleMetadata { Name = "test", Created = "2025-01-01T00:00:00Z" },
            Identities =
            [
                new TrustedIdentity
                {
                    Issuer = issuer,
                    SubjectPattern = subjectPattern,
                    DisplayName = displayName,
                    NotAfter = notAfter
                }
            ]
        };
    }

    private static TrustBundle CreateBundleWithKey(string fingerprint, string displayName)
    {
        return new TrustBundle
        {
            Metadata = new BundleMetadata { Name = "test", Created = "2025-01-01T00:00:00Z" },
            Keys =
            [
                new TrustedKeyEntry
                {
                    Fingerprint = fingerprint,
                    DisplayName = displayName
                }
            ]
        };
    }
}
