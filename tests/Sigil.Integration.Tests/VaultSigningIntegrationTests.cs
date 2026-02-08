using Sigil.Crypto;
using Sigil.Keys;
using Sigil.Signing;
using Sigil.Trust;
using Sigil.Vault;

namespace Sigil.Integration.Tests;

public class VaultSigningIntegrationTests
{
    [Fact]
    public async Task FakeVaultSigner_SignAsync_VerifyRoundTrip()
    {
        using var inner = ECDsaP256Signer.Generate();
        using var signer = new FakeVaultSigner(inner);
        var fingerprint = KeyFingerprint.Compute(signer.PublicKey);

        var artifactPath = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(artifactPath, "vault-signed artifact content");
            var artifactBytes = await File.ReadAllBytesAsync(artifactPath);

            var envelope = await ArtifactSigner.SignAsync(artifactPath, signer, fingerprint, "vault-test");

            Assert.NotNull(envelope);
            Assert.Single(envelope.Signatures);

            // Verify produces identical envelope format
            var result = SignatureValidator.Verify(artifactBytes, envelope);
            Assert.True(result.AllSignaturesValid);
        }
        finally
        {
            File.Delete(artifactPath);
        }
    }

    [Fact]
    public async Task FakeVaultSigner_SignAsync_Serialize_Deserialize_Verify()
    {
        using var inner = ECDsaP256Signer.Generate();
        using var signer = new FakeVaultSigner(inner);
        var fingerprint = KeyFingerprint.Compute(signer.PublicKey);

        var artifactPath = Path.GetTempFileName();
        try
        {
            var content = "round-trip test"u8.ToArray();
            await File.WriteAllBytesAsync(artifactPath, content);

            var envelope = await ArtifactSigner.SignAsync(artifactPath, signer, fingerprint);

            // Serialize → Deserialize round-trip
            var json = ArtifactSigner.Serialize(envelope);
            var deserialized = ArtifactSigner.Deserialize(json);

            // Verify deserialized envelope
            var result = SignatureValidator.Verify(content, deserialized);
            Assert.True(result.AllSignaturesValid);
        }
        finally
        {
            File.Delete(artifactPath);
        }
    }

    [Fact]
    public async Task FakeVaultSigner_BundleSignAsync_Verify()
    {
        using var inner = ECDsaP256Signer.Generate();
        using var signer = new FakeVaultSigner(inner);
        var fingerprint = KeyFingerprint.Compute(signer.PublicKey);

        var bundle = new TrustBundle
        {
            Metadata = new BundleMetadata
            {
                Name = "vault-bundle-test",
                Created = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ",
                    System.Globalization.CultureInfo.InvariantCulture)
            },
            Keys = [new TrustedKeyEntry { Fingerprint = fingerprint.Value, DisplayName = "vault-key" }]
        };

        var signResult = await BundleSigner.SignAsync(bundle, signer);
        Assert.True(signResult.IsSuccess);

        var serializeResult = BundleSigner.Serialize(signResult.Value);
        Assert.True(serializeResult.IsSuccess);

        var verifyResult = BundleSigner.Verify(serializeResult.Value, fingerprint.Value);
        Assert.True(verifyResult.IsSuccess);
        Assert.True(verifyResult.Value);
    }

    [Fact]
    public async Task FakeVaultSigner_SignAsync_TrustEvaluate_Trusted()
    {
        using var inner = ECDsaP256Signer.Generate();
        using var signer = new FakeVaultSigner(inner);
        var fingerprint = KeyFingerprint.Compute(signer.PublicKey);

        var artifactPath = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(artifactPath, "trust-eval content");
            var artifactBytes = await File.ReadAllBytesAsync(artifactPath);

            var envelope = await ArtifactSigner.SignAsync(artifactPath, signer, fingerprint);
            var verificationResult = SignatureValidator.Verify(artifactBytes, envelope);
            Assert.True(verificationResult.AllSignaturesValid);

            // Create a trust bundle that trusts this key
            var bundle = new TrustBundle
            {
                Metadata = new BundleMetadata
                {
                    Name = "eval-test",
                    Created = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ",
                        System.Globalization.CultureInfo.InvariantCulture)
                },
                Keys = [new TrustedKeyEntry { Fingerprint = fingerprint.Value }]
            };

            var evalResult = TrustEvaluator.Evaluate(verificationResult, bundle, "trust-eval content");

            Assert.True(evalResult.AllTrusted);
            Assert.Single(evalResult.Signatures);
            Assert.Equal(TrustDecision.Trusted, evalResult.Signatures[0].Decision);
        }
        finally
        {
            File.Delete(artifactPath);
        }
    }

    [Fact]
    public void FakeVaultSigner_SyncSign_ThrowsNotSupported()
    {
        using var inner = ECDsaP256Signer.Generate();
        using var signer = new FakeVaultSigner(inner);

        Assert.Throws<NotSupportedException>(() => signer.Sign(new byte[] { 1, 2, 3 }));
    }

    [Fact]
    public void FakeVaultSigner_CanExportPrivateKey_IsFalse()
    {
        using var inner = ECDsaP256Signer.Generate();
        using var signer = new FakeVaultSigner(inner);

        Assert.False(signer.CanExportPrivateKey);
    }

    [Fact]
    public void FakeVaultSigner_ExportPrivateKeyPemBytes_Throws()
    {
        using var inner = ECDsaP256Signer.Generate();
        using var signer = new FakeVaultSigner(inner);

        Assert.Throws<NotSupportedException>(() => signer.ExportPrivateKeyPemBytes());
    }

    private sealed class FakeVaultSigner : VaultSignerBase
    {
        private readonly ISigner _inner;

        public FakeVaultSigner(ISigner inner) => _inner = inner;

        public override SigningAlgorithm Algorithm => _inner.Algorithm;
        public override byte[] PublicKey => _inner.PublicKey;

        public override ValueTask<byte[]> SignAsync(byte[] data, CancellationToken cancellationToken = default)
            => new(_inner.Sign(data));

        public override void Dispose() => _inner.Dispose();
    }
}
