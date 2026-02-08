using System.Security.Cryptography;
using Sigil.Crypto;
using Sigil.Keys;
using Sigil.Signing;

namespace Sigil.Integration.Tests;

public class SignVerifyIntegrationTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _artifactPath;

    public SignVerifyIntegrationTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-integ-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
        _artifactPath = Path.Combine(_tempDir, "test-artifact.bin");
        File.WriteAllBytes(_artifactPath, RandomNumberGenerator.GetBytes(1024));
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    [Fact]
    public void EcdsaP256_SignVerify_RoundTrip()
    {
        using var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var fp = KeyFingerprint.Compute(signer.PublicKey);

        var envelope = ArtifactSigner.Sign(_artifactPath, signer, fp);
        var json = ArtifactSigner.Serialize(envelope);
        var deserialized = ArtifactSigner.Deserialize(json);

        var result = SignatureValidator.Verify(_artifactPath, deserialized);

        Assert.True(result.ArtifactDigestMatch);
        Assert.True(result.AllSignaturesValid);
        Assert.Equal("ecdsa-p256", result.Signatures[0].Algorithm);
    }

    [Fact]
    public void EcdsaP384_SignVerify_RoundTrip()
    {
        using var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP384);
        var fp = KeyFingerprint.Compute(signer.PublicKey);

        var envelope = ArtifactSigner.Sign(_artifactPath, signer, fp);
        var json = ArtifactSigner.Serialize(envelope);
        var deserialized = ArtifactSigner.Deserialize(json);

        var result = SignatureValidator.Verify(_artifactPath, deserialized);

        Assert.True(result.ArtifactDigestMatch);
        Assert.True(result.AllSignaturesValid);
        Assert.Equal("ecdsa-p384", result.Signatures[0].Algorithm);
    }

    [Fact]
    public void Rsa_SignVerify_RoundTrip()
    {
        using var signer = SignerFactory.Generate(SigningAlgorithm.Rsa);
        var fp = KeyFingerprint.Compute(signer.PublicKey);

        var envelope = ArtifactSigner.Sign(_artifactPath, signer, fp);
        var json = ArtifactSigner.Serialize(envelope);
        var deserialized = ArtifactSigner.Deserialize(json);

        var result = SignatureValidator.Verify(_artifactPath, deserialized);

        Assert.True(result.ArtifactDigestMatch);
        Assert.True(result.AllSignaturesValid);
        Assert.Equal("rsa-pss-sha256", result.Signatures[0].Algorithm);
    }

    [Fact]
    public void MLDsa65_SignVerify_RoundTrip()
    {
        if (!MLDsa.IsSupported)
            return; // Skip on platforms without ML-DSA support

        using var signer = SignerFactory.Generate(SigningAlgorithm.MLDsa65);
        var fp = KeyFingerprint.Compute(signer.PublicKey);

        var envelope = ArtifactSigner.Sign(_artifactPath, signer, fp);
        var json = ArtifactSigner.Serialize(envelope);
        var deserialized = ArtifactSigner.Deserialize(json);

        var result = SignatureValidator.Verify(_artifactPath, deserialized);

        Assert.True(result.ArtifactDigestMatch);
        Assert.True(result.AllSignaturesValid);
        Assert.Equal("ml-dsa-65", result.Signatures[0].Algorithm);
    }

    [Fact]
    public void Ephemeral_SignVerify_NoKeyPersistence()
    {
        using var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var fp = KeyFingerprint.Compute(signer.PublicKey);
        var envelope = ArtifactSigner.Sign(_artifactPath, signer, fp, "ephemeral-test");

        // Verify works because public key is embedded in envelope
        var result = SignatureValidator.Verify(_artifactPath, envelope);
        Assert.True(result.AllSignaturesValid);
    }

    [Fact]
    public void Persistent_SignVerify_WithPemFile()
    {
        using var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var fp = KeyFingerprint.Compute(signer.PublicKey);

        // Save key to PEM
        var pemPath = Path.Combine(_tempDir, "key.pem");
        File.WriteAllBytes(pemPath, signer.ExportPrivateKeyPemBytes());

        var envelope = ArtifactSigner.Sign(_artifactPath, signer, fp, "persistent-test");

        // Load from PEM and verify fingerprint matches
        using var loaded = SignerFactory.CreateFromPem(File.ReadAllText(pemPath));
        Assert.Equal(signer.PublicKey, loaded.PublicKey);

        var result = SignatureValidator.Verify(_artifactPath, envelope);
        Assert.True(result.AllSignaturesValid);
    }

    [Fact]
    public void MultiSignature_TwoAlgorithms()
    {
        using var signer1 = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        using var signer2 = SignerFactory.Generate(SigningAlgorithm.ECDsaP384);
        var fp1 = KeyFingerprint.Compute(signer1.PublicKey);
        var fp2 = KeyFingerprint.Compute(signer2.PublicKey);

        var artifactBytes = File.ReadAllBytes(_artifactPath);
        var envelope = ArtifactSigner.Sign(_artifactPath, signer1, fp1, "author");
        ArtifactSigner.AppendSignature(envelope, artifactBytes, signer2, fp2, "reviewer");

        Assert.Equal(2, envelope.Signatures.Count);

        var result = SignatureValidator.Verify(_artifactPath, envelope);
        Assert.True(result.AllSignaturesValid);
        Assert.Equal(2, result.Signatures.Count);
        Assert.Equal("ecdsa-p256", result.Signatures[0].Algorithm);
        Assert.Equal("ecdsa-p384", result.Signatures[1].Algorithm);
    }
}
