using System.Globalization;
using System.Security.Cryptography;
using Sigil.Crypto;
using Sigil.Keys;
using Sigil.Signing;
using Sigil.Trust;

namespace Sigil.Integration.Tests;

public class TrustBundleIntegrationTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _artifactPath;

    public TrustBundleIntegrationTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-integ-trust-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
        _artifactPath = Path.Combine(_tempDir, "artifact.bin");
        File.WriteAllBytes(_artifactPath, RandomNumberGenerator.GetBytes(512));
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    [Fact]
    public void CreateBundle_AddKeys_Sign_Verify_Trusted()
    {
        // Create authority key and signing key
        using var authority = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        using var signingKey = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var authorityFp = KeyFingerprint.Compute(authority.PublicKey);
        var signerFp = KeyFingerprint.Compute(signingKey.PublicKey);

        // Create trust bundle
        var bundle = new TrustBundle
        {
            Metadata = new BundleMetadata
            {
                Name = "Test Bundle",
                Created = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture)
            },
            Keys = [new TrustedKeyEntry { Fingerprint = signerFp.Value, DisplayName = "Test Signer" }]
        };

        // Sign bundle
        var signResult = BundleSigner.Sign(bundle, authority);
        Assert.True(signResult.IsSuccess);

        // Serialize and verify bundle
        var serResult = BundleSigner.Serialize(signResult.Value);
        Assert.True(serResult.IsSuccess);
        var bundleJson = serResult.Value;

        var verifyBundle = BundleSigner.Verify(bundleJson, authorityFp.Value);
        Assert.True(verifyBundle.IsSuccess);
        Assert.True(verifyBundle.Value);

        // Sign artifact
        var envelope = ArtifactSigner.Sign(_artifactPath, signingKey, signerFp);
        var verification = SignatureValidator.Verify(_artifactPath, envelope);
        Assert.True(verification.AllSignaturesValid);

        // Evaluate trust
        var trustResult = TrustEvaluator.Evaluate(verification, signResult.Value, envelope.Subject.Name);
        Assert.True(trustResult.AllTrusted);
        Assert.Equal(TrustDecision.Trusted, trustResult.Signatures[0].Decision);
    }

    [Fact]
    public void Endorsement_Workflow_TrustedViaEndorsement()
    {
        using var authority = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        using var endorser = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        using var endorsed = SignerFactory.Generate(SigningAlgorithm.ECDsaP384);
        var authorityFp = KeyFingerprint.Compute(authority.PublicKey);
        var endorserFp = KeyFingerprint.Compute(endorser.PublicKey);
        var endorsedFp = KeyFingerprint.Compute(endorsed.PublicKey);

        var bundle = new TrustBundle
        {
            Metadata = new BundleMetadata
            {
                Name = "Endorsement Bundle",
                Created = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture)
            },
            Keys = [new TrustedKeyEntry { Fingerprint = endorserFp.Value, DisplayName = "Endorser" }],
            Endorsements =
            [
                new Endorsement
                {
                    Endorser = endorserFp.Value,
                    Endorsed = endorsedFp.Value,
                    Statement = "Approved for production use",
                    Timestamp = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture)
                }
            ]
        };

        var signResult = BundleSigner.Sign(bundle, authority);
        Assert.True(signResult.IsSuccess);

        // Sign artifact with the endorsed key
        var envelope = ArtifactSigner.Sign(_artifactPath, endorsed, endorsedFp);
        var verification = SignatureValidator.Verify(_artifactPath, envelope);
        Assert.True(verification.AllSignaturesValid);

        var trustResult = TrustEvaluator.Evaluate(verification, signResult.Value, envelope.Subject.Name);
        Assert.True(trustResult.AnyTrusted);
        Assert.Equal(TrustDecision.TrustedViaEndorsement, trustResult.Signatures[0].Decision);
    }

    [Fact]
    public void ExpiredKey_Returns_Expired()
    {
        using var authority = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        using var signingKey = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var authorityFp = KeyFingerprint.Compute(authority.PublicKey);
        var signerFp = KeyFingerprint.Compute(signingKey.PublicKey);

        var bundle = new TrustBundle
        {
            Metadata = new BundleMetadata
            {
                Name = "Expiry Bundle",
                Created = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture)
            },
            Keys =
            [
                new TrustedKeyEntry
                {
                    Fingerprint = signerFp.Value,
                    NotAfter = "2020-01-01T00:00:00Z" // Already expired
                }
            ]
        };

        var signResult = BundleSigner.Sign(bundle, authority);
        Assert.True(signResult.IsSuccess);

        var envelope = ArtifactSigner.Sign(_artifactPath, signingKey, signerFp);
        var verification = SignatureValidator.Verify(_artifactPath, envelope);

        var trustResult = TrustEvaluator.Evaluate(verification, signResult.Value, envelope.Subject.Name);
        Assert.Equal(TrustDecision.Expired, trustResult.Signatures[0].Decision);
    }

    [Fact]
    public void ScopeRestriction_ArtifactMismatch_Returns_ScopeMismatch()
    {
        using var authority = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        using var signingKey = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var authorityFp = KeyFingerprint.Compute(authority.PublicKey);
        var signerFp = KeyFingerprint.Compute(signingKey.PublicKey);

        var bundle = new TrustBundle
        {
            Metadata = new BundleMetadata
            {
                Name = "Scoped Bundle",
                Created = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture)
            },
            Keys =
            [
                new TrustedKeyEntry
                {
                    Fingerprint = signerFp.Value,
                    Scopes = new TrustScopes
                    {
                        NamePatterns = ["only-this-artifact.tar.gz"]
                    }
                }
            ]
        };

        var signResult = BundleSigner.Sign(bundle, authority);
        Assert.True(signResult.IsSuccess);

        var envelope = ArtifactSigner.Sign(_artifactPath, signingKey, signerFp);
        var verification = SignatureValidator.Verify(_artifactPath, envelope);

        var trustResult = TrustEvaluator.Evaluate(verification, signResult.Value, envelope.Subject.Name);
        Assert.Equal(TrustDecision.ScopeMismatch, trustResult.Signatures[0].Decision);
    }

    [Fact]
    public void UntrustedKey_Returns_Untrusted()
    {
        using var authority = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        using var signingKey = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        using var unknownKey = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var authorityFp = KeyFingerprint.Compute(authority.PublicKey);
        var signerFp = KeyFingerprint.Compute(signingKey.PublicKey);
        var unknownFp = KeyFingerprint.Compute(unknownKey.PublicKey);

        // Bundle only trusts signingKey, not unknownKey
        var bundle = new TrustBundle
        {
            Metadata = new BundleMetadata
            {
                Name = "Limited Bundle",
                Created = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture)
            },
            Keys = [new TrustedKeyEntry { Fingerprint = signerFp.Value }]
        };

        var signResult = BundleSigner.Sign(bundle, authority);
        Assert.True(signResult.IsSuccess);

        // Sign with the unknown key
        var envelope = ArtifactSigner.Sign(_artifactPath, unknownKey, unknownFp);
        var verification = SignatureValidator.Verify(_artifactPath, envelope);

        var trustResult = TrustEvaluator.Evaluate(verification, signResult.Value, envelope.Subject.Name);
        Assert.Equal(TrustDecision.Untrusted, trustResult.Signatures[0].Decision);
    }
}
