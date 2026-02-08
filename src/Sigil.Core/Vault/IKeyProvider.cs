using Sigil.Crypto;

namespace Sigil.Vault;

public interface IKeyProvider : IAsyncDisposable
{
    Task<VaultResult<ISigner>> GetSignerAsync(string keyReference, CancellationToken ct = default);
    Task<VaultResult<byte[]>> GetPublicKeyAsync(string keyReference, CancellationToken ct = default);
}
