using Sigil.Crypto;
using Sigil.Vault;

namespace Sigil.Core.Tests.Vault;

public class VaultSignerBaseTests
{
    [Fact]
    public void Sign_ThrowsNotSupportedException()
    {
        using var inner = ECDsaP256Signer.Generate();
        using var signer = new FakeVaultSigner(inner);

        Assert.Throws<NotSupportedException>(() => signer.Sign(new byte[] { 1, 2, 3 }));
    }

    [Fact]
    public void CanExportPrivateKey_ReturnsFalse()
    {
        using var inner = ECDsaP256Signer.Generate();
        using var signer = new FakeVaultSigner(inner);

        Assert.False(signer.CanExportPrivateKey);
    }

    [Fact]
    public void ExportPrivateKeyPemBytes_ThrowsNotSupportedException()
    {
        using var inner = ECDsaP256Signer.Generate();
        using var signer = new FakeVaultSigner(inner);

        Assert.Throws<NotSupportedException>(() => signer.ExportPrivateKeyPemBytes());
    }

    [Fact]
    public void ExportEncryptedPrivateKeyPemBytes_ThrowsNotSupportedException()
    {
        using var inner = ECDsaP256Signer.Generate();
        using var signer = new FakeVaultSigner(inner);

        Assert.Throws<NotSupportedException>(() => signer.ExportEncryptedPrivateKeyPemBytes("password"));
    }

    [Fact]
    public async Task SignAsync_DelegatesToOverride()
    {
        using var inner = ECDsaP256Signer.Generate();
        using var signer = new FakeVaultSigner(inner);
        var data = new byte[] { 1, 2, 3 };

        var signature = await signer.SignAsync(data);

        Assert.NotNull(signature);
        Assert.True(signature.Length > 0);
    }

    [Fact]
    public void Algorithm_DelegatesToOverride()
    {
        using var inner = ECDsaP256Signer.Generate();
        using var signer = new FakeVaultSigner(inner);

        Assert.Equal(SigningAlgorithm.ECDsaP256, signer.Algorithm);
    }

    [Fact]
    public void PublicKey_DelegatesToOverride()
    {
        using var inner = ECDsaP256Signer.Generate();
        using var signer = new FakeVaultSigner(inner);

        Assert.Equal(inner.PublicKey, signer.PublicKey);
    }

    [Fact]
    public void ExportPublicKeyPem_FormatsSpkiToPem()
    {
        using var inner = ECDsaP256Signer.Generate();
        using var signer = new FakeVaultSigner(inner);

        var pem = signer.ExportPublicKeyPem();

        Assert.StartsWith("-----BEGIN PUBLIC KEY-----", pem);
        Assert.Contains("-----END PUBLIC KEY-----", pem);
    }

    [Fact]
    public async Task SignAsync_ProducesSameSignatureAsInnerSigner()
    {
        using var inner = ECDsaP256Signer.Generate();
        using var signer = new FakeVaultSigner(inner);
        var data = new byte[] { 4, 5, 6 };

        // FakeVaultSigner delegates to inner.Sign(), so the signature should verify
        var signature = await signer.SignAsync(data);

        var verifier = ECDsaP256Verifier.FromPublicKey(inner.PublicKey);
        Assert.True(verifier.Verify(data, signature));
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
