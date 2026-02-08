namespace Sigil.Crypto;

public interface ISigner : IDisposable
{
    SigningAlgorithm Algorithm { get; }
    byte[] PublicKey { get; }
    byte[] Sign(byte[] data);
    string ExportPublicKeyPem();
    byte[] ExportPrivateKeyPemBytes();
    byte[] ExportEncryptedPrivateKeyPemBytes(ReadOnlySpan<char> password);

    /// <summary>
    /// Asynchronously signs data. Vault signers override this to call vault APIs.
    /// Local signers use the default implementation which delegates to Sign().
    /// </summary>
    ValueTask<byte[]> SignAsync(byte[] data, CancellationToken cancellationToken = default)
        => new(Sign(data));

    /// <summary>
    /// Whether this signer can export private key material.
    /// Returns false for vault-backed signers where the key stays in the vault.
    /// </summary>
    bool CanExportPrivateKey => true;
}

public interface IVerifier : IDisposable
{
    SigningAlgorithm Algorithm { get; }
    byte[] PublicKey { get; }
    bool Verify(byte[] data, byte[] signature);
}
