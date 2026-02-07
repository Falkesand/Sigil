using System.Globalization;
using Sigil.Crypto;
using Sigil.Keys;
using Sigil.Signing;
using Sigil.Trust;

namespace Sigil.Core.Tests.Trust;

public class TrustEvaluatorTests : IDisposable
{
    private readonly ISigner _signer;
    private readonly KeyFingerprint _fingerprint;
    private readonly string _tempDir;

    public TrustEvaluatorTests()
    {
        _signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        _fingerprint = KeyFingerprint.Compute(_signer.PublicKey);
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-trust-eval-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        _signer.Dispose();
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    [Fact]
    public void Trusted_when_key_in_bundle_and_crypto_valid()
    {
        var bundle = CreateBundleWithKey(_fingerprint.Value, "Test Key");
        var verification = CreateVerificationResult(valid: true);

        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz");

        Assert.Single(result.Signatures);
        Assert.Equal(TrustDecision.Trusted, result.Signatures[0].Decision);
        Assert.Equal("Test Key", result.Signatures[0].DisplayName);
        Assert.True(result.AllTrusted);
    }

    [Fact]
    public void Untrusted_when_crypto_invalid()
    {
        var bundle = CreateBundleWithKey(_fingerprint.Value, "Test Key");
        var verification = CreateVerificationResult(valid: false);

        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz");

        Assert.Single(result.Signatures);
        Assert.Equal(TrustDecision.Untrusted, result.Signatures[0].Decision);
        Assert.Contains("crypto", result.Signatures[0].Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Untrusted_when_key_not_in_bundle()
    {
        var bundle = CreateBundleWithKey("sha256:" + new string('f', 64), "Other Key");
        var verification = CreateVerificationResult(valid: true);

        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz");

        Assert.Single(result.Signatures);
        Assert.Equal(TrustDecision.Untrusted, result.Signatures[0].Decision);
        Assert.False(result.AnyTrusted);
    }

    [Fact]
    public void Expired_when_key_past_notAfter()
    {
        var bundle = CreateBundleWithKey(_fingerprint.Value, "Expired Key",
            notAfter: "2020-01-01T00:00:00Z");
        var verification = CreateVerificationResult(valid: true);

        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz");

        Assert.Single(result.Signatures);
        Assert.Equal(TrustDecision.Expired, result.Signatures[0].Decision);
    }

    [Fact]
    public void ScopeMismatch_when_name_pattern_fails()
    {
        var bundle = CreateBundleWithKey(_fingerprint.Value, "Scoped Key",
            scopes: new TrustScopes { NamePatterns = ["*.tar.gz"] });
        var verification = CreateVerificationResult(valid: true);

        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.zip");

        Assert.Single(result.Signatures);
        Assert.Equal(TrustDecision.ScopeMismatch, result.Signatures[0].Decision);
    }

    [Fact]
    public void ScopeMismatch_when_label_fails()
    {
        var bundle = CreateBundleWithKey(_fingerprint.Value, "Scoped Key",
            scopes: new TrustScopes { Labels = ["release"] });
        var verification = CreateVerificationResult(valid: true, label: "dev");

        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz");

        Assert.Single(result.Signatures);
        Assert.Equal(TrustDecision.ScopeMismatch, result.Signatures[0].Decision);
    }

    [Fact]
    public void ScopeMismatch_when_algorithm_fails()
    {
        var bundle = CreateBundleWithKey(_fingerprint.Value, "Scoped Key",
            scopes: new TrustScopes { Algorithms = ["rsa-pss-sha256"] });
        var verification = CreateVerificationResult(valid: true);

        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz");

        Assert.Single(result.Signatures);
        Assert.Equal(TrustDecision.ScopeMismatch, result.Signatures[0].Decision);
    }

    [Fact]
    public void Custom_evaluation_time_affects_expiry()
    {
        var bundle = CreateBundleWithKey(_fingerprint.Value, "Key",
            notAfter: "2026-06-01T00:00:00Z");
        var verification = CreateVerificationResult(valid: true);

        // Before expiry
        var beforeResult = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz",
            evaluationTime: DateTimeOffset.Parse("2026-01-01T00:00:00Z", CultureInfo.InvariantCulture));
        Assert.Equal(TrustDecision.Trusted, beforeResult.Signatures[0].Decision);

        // After expiry
        var afterResult = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz",
            evaluationTime: DateTimeOffset.Parse("2026-07-01T00:00:00Z", CultureInfo.InvariantCulture));
        Assert.Equal(TrustDecision.Expired, afterResult.Signatures[0].Decision);
    }

    [Fact]
    public void Multiple_signatures_evaluated_independently()
    {
        using var signer2 = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var fp2 = KeyFingerprint.Compute(signer2.PublicKey);

        var bundle = new TrustBundle
        {
            Metadata = new BundleMetadata { Name = "multi", Created = "2026-02-08T12:00:00Z" },
            Keys =
            [
                new TrustedKeyEntry { Fingerprint = _fingerprint.Value, DisplayName = "Key 1" },
                // Key 2 not in bundle
            ]
        };

        var verification = new VerificationResult
        {
            ArtifactDigestMatch = true,
            Signatures =
            [
                new SignatureVerificationResult
                {
                    KeyId = _fingerprint.Value, IsValid = true, Algorithm = "ecdsa-p256", Label = null
                },
                new SignatureVerificationResult
                {
                    KeyId = fp2.Value, IsValid = true, Algorithm = "ecdsa-p256", Label = null
                }
            ]
        };

        var result = TrustEvaluator.Evaluate(verification, bundle, "artifact.tar.gz");

        Assert.Equal(2, result.Signatures.Count);
        Assert.Equal(TrustDecision.Trusted, result.Signatures[0].Decision);
        Assert.Equal(TrustDecision.Untrusted, result.Signatures[1].Decision);
        Assert.True(result.AnyTrusted);
        Assert.False(result.AllTrusted);
    }

    private VerificationResult CreateVerificationResult(bool valid, string? label = null, string? algorithm = "ecdsa-p256") =>
        new()
        {
            ArtifactDigestMatch = true,
            Signatures =
            [
                new SignatureVerificationResult
                {
                    KeyId = _fingerprint.Value,
                    IsValid = valid,
                    Algorithm = algorithm,
                    Label = label
                }
            ]
        };

    private static TrustBundle CreateBundleWithKey(string fingerprint, string displayName,
        string? notAfter = null, TrustScopes? scopes = null) => new()
    {
        Metadata = new BundleMetadata { Name = "test", Created = "2026-02-08T12:00:00Z" },
        Keys =
        [
            new TrustedKeyEntry
            {
                Fingerprint = fingerprint,
                DisplayName = displayName,
                NotAfter = notAfter,
                Scopes = scopes
            }
        ]
    };
}
