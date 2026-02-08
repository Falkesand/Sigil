using Sigil.Crypto;
using Sigil.Vault;

namespace Sigil.Core.Tests.Vault;

public class KeyProviderTests
{
    [Fact]
    public async Task FakeKeyProvider_GetSignerAsync_ReturnsVaultSigner()
    {
        await using var provider = new FakeKeyProvider();

        var result = await provider.GetSignerAsync("test-key");

        Assert.True(result.IsSuccess);
        using var signer = result.Value;
        Assert.Equal(SigningAlgorithm.ECDsaP256, signer.Algorithm);
        Assert.False(signer.CanExportPrivateKey);
    }

    [Fact]
    public async Task FakeKeyProvider_GetPublicKeyAsync_ReturnsSPKI()
    {
        await using var provider = new FakeKeyProvider();

        var result = await provider.GetPublicKeyAsync("test-key");

        Assert.True(result.IsSuccess);
        Assert.True(result.Value.Length > 0);
    }

    [Fact]
    public async Task FakeKeyProvider_GetSignerAsync_UnknownKey_ReturnsFailure()
    {
        await using var provider = new FakeKeyProvider();

        var result = await provider.GetSignerAsync("unknown-key");

        Assert.False(result.IsSuccess);
        Assert.Equal(VaultErrorKind.KeyNotFound, result.ErrorKind);
    }

    [Fact]
    public async Task FakeKeyProvider_Signer_SignAsync_ProducesValidSignature()
    {
        await using var provider = new FakeKeyProvider();
        var signerResult = await provider.GetSignerAsync("test-key");
        using var signer = signerResult.Value;

        var data = new byte[] { 1, 2, 3 };
        var signature = await signer.SignAsync(data);

        Assert.NotNull(signature);
        Assert.True(signature.Length > 0);
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

    private sealed class FakeKeyProvider : IKeyProvider
    {
        private ECDsaP256Signer? _signer;

        public Task<VaultResult<ISigner>> GetSignerAsync(string keyReference, CancellationToken ct = default)
        {
            if (keyReference != "test-key")
                return Task.FromResult(VaultResult<ISigner>.Fail(VaultErrorKind.KeyNotFound, $"Key '{keyReference}' not found."));

            _signer = ECDsaP256Signer.Generate();
            ISigner vaultSigner = new FakeVaultSigner(_signer);
            return Task.FromResult(VaultResult<ISigner>.Ok(vaultSigner));
        }

        public Task<VaultResult<byte[]>> GetPublicKeyAsync(string keyReference, CancellationToken ct = default)
        {
            if (keyReference != "test-key")
                return Task.FromResult(VaultResult<byte[]>.Fail(VaultErrorKind.KeyNotFound, $"Key '{keyReference}' not found."));

            using var signer = ECDsaP256Signer.Generate();
            return Task.FromResult(VaultResult<byte[]>.Ok(signer.PublicKey));
        }

        public ValueTask DisposeAsync()
        {
            _signer?.Dispose();
            return ValueTask.CompletedTask;
        }
    }
}
