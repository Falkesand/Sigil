using System.Text;
using Sigil.Crypto;
using Sigil.Keys;
using Sigil.Signing;

namespace Sigil.Core.Tests.Signing;

public class MultiAlgorithmSigningTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _artifactPath;

    public MultiAlgorithmSigningTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-test-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
        _artifactPath = Path.Combine(_tempDir, "test-artifact.txt");
        File.WriteAllText(_artifactPath, "Hello, multi-algorithm signing!");
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    [Theory]
    [InlineData(SigningAlgorithm.ECDsaP256)]
    [InlineData(SigningAlgorithm.ECDsaP384)]
    [InlineData(SigningAlgorithm.Rsa)]
    public void SignAndVerify_RoundTrip_PerAlgorithm(SigningAlgorithm algorithm)
    {
        using var signer = SignerFactory.Generate(algorithm);
        var fingerprint = KeyFingerprint.Compute(signer.PublicKey);

        var envelope = ArtifactSigner.Sign(_artifactPath, signer, fingerprint, "test-label");
        var json = ArtifactSigner.Serialize(envelope);
        var deserialized = ArtifactSigner.Deserialize(json);

        var result = SignatureValidator.Verify(_artifactPath, deserialized);

        Assert.True(result.ArtifactDigestMatch);
        Assert.Single(result.Signatures);
        Assert.True(result.Signatures[0].IsValid);
        Assert.Equal(algorithm.ToCanonicalName(), deserialized.Signatures[0].Algorithm);
    }

    [Theory]
    [InlineData(SigningAlgorithm.ECDsaP256)]
    [InlineData(SigningAlgorithm.ECDsaP384)]
    [InlineData(SigningAlgorithm.Rsa)]
    public void SignAndVerify_TamperedArtifact_Fails(SigningAlgorithm algorithm)
    {
        using var signer = SignerFactory.Generate(algorithm);
        var fingerprint = KeyFingerprint.Compute(signer.PublicKey);

        var envelope = ArtifactSigner.Sign(_artifactPath, signer, fingerprint);
        var json = ArtifactSigner.Serialize(envelope);
        var deserialized = ArtifactSigner.Deserialize(json);

        // Tamper with the artifact
        var tamperedPath = Path.Combine(_tempDir, "tampered.txt");
        File.WriteAllText(tamperedPath, "Tampered content!");

        var result = SignatureValidator.Verify(tamperedPath, deserialized);

        Assert.False(result.ArtifactDigestMatch);
    }

    [Fact]
    public void MixedAlgorithm_MultiSignature_Envelope()
    {
        var artifactBytes = File.ReadAllBytes(_artifactPath);

        // Create signers for each algorithm
        using var p256Signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        using var p384Signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP384);
        using var rsaSigner = SignerFactory.Generate(SigningAlgorithm.Rsa);

        var p256Fp = KeyFingerprint.Compute(p256Signer.PublicKey);
        var p384Fp = KeyFingerprint.Compute(p384Signer.PublicKey);
        var rsaFp = KeyFingerprint.Compute(rsaSigner.PublicKey);

        // Sign with P-256 first
        var envelope = ArtifactSigner.Sign(_artifactPath, p256Signer, p256Fp, "p256");

        // Append P-384 and RSA signatures
        ArtifactSigner.AppendSignature(envelope, artifactBytes, p384Signer, p384Fp, "p384");
        ArtifactSigner.AppendSignature(envelope, artifactBytes, rsaSigner, rsaFp, "rsa");

        Assert.Equal(3, envelope.Signatures.Count);

        // Serialize and deserialize
        var json = ArtifactSigner.Serialize(envelope);
        var deserialized = ArtifactSigner.Deserialize(json);

        // Verify all signatures
        var result = SignatureValidator.Verify(_artifactPath, deserialized);

        Assert.True(result.ArtifactDigestMatch);
        Assert.Equal(3, result.Signatures.Count);
        Assert.True(result.AllSignaturesValid);

        // Verify algorithm names
        Assert.Equal("ecdsa-p256", deserialized.Signatures[0].Algorithm);
        Assert.Equal("ecdsa-p384", deserialized.Signatures[1].Algorithm);
        Assert.Equal("rsa-pss-sha256", deserialized.Signatures[2].Algorithm);
    }

    [Fact]
    public void CrossAlgorithm_TamperedSignature_Fails()
    {
        using var p256Signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        using var p384Signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP384);

        var data = Encoding.UTF8.GetBytes("cross-algorithm test");

        // Sign with P-256
        var signature = p256Signer.Sign(data);

        // Verify with P-384 verifier should fail
        using var p384Verifier = ECDsaP384Verifier.FromPublicKey(p384Signer.PublicKey);
        Assert.False(p384Verifier.Verify(data, signature));
    }

    [Fact]
    public void VerifierFactory_CorrectlyDispatches_AllAlgorithms()
    {
        var algorithms = new[] { SigningAlgorithm.ECDsaP256, SigningAlgorithm.ECDsaP384, SigningAlgorithm.Rsa };

        foreach (var algorithm in algorithms)
        {
            using var signer = SignerFactory.Generate(algorithm);
            var data = Encoding.UTF8.GetBytes($"dispatch test for {algorithm}");
            var signature = signer.Sign(data);

            using var verifier = VerifierFactory.CreateFromPublicKey(
                signer.PublicKey, algorithm.ToCanonicalName());

            Assert.True(verifier.Verify(data, signature));
            Assert.Equal(algorithm, verifier.Algorithm);
        }
    }

    [Theory]
    [InlineData(SigningAlgorithm.ECDsaP256)]
    [InlineData(SigningAlgorithm.ECDsaP384)]
    [InlineData(SigningAlgorithm.Rsa)]
    public void PemExportImport_ThenSign_Verifies(SigningAlgorithm algorithm)
    {
        // Generate, export PEM, re-import via factory, sign, verify
        using var original = SignerFactory.Generate(algorithm);
        var pemBytes = original.ExportPrivateKeyPemBytes();
        var pemChars = Encoding.UTF8.GetChars(pemBytes);

        using var restored = SignerFactory.CreateFromPem(pemChars);
        Assert.Equal(algorithm, restored.Algorithm);

        var data = Encoding.UTF8.GetBytes("pem round trip integration");
        var signature = restored.Sign(data);

        using var verifier = VerifierFactory.CreateFromPublicKey(
            original.PublicKey, algorithm.ToCanonicalName());
        Assert.True(verifier.Verify(data, signature));
    }
}
