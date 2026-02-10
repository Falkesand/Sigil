using System.Security.Cryptography;

namespace Sigil.Crypto;

/// <summary>
/// Verifies ECDSA P-521 signatures. BCL-only, no external dependencies.
/// </summary>
public sealed class ECDsaP521Verifier : IVerifier
{
    private readonly ECDsa _key;
    private bool _disposed;

    public SigningAlgorithm Algorithm => SigningAlgorithm.ECDsaP521;

    public byte[] PublicKey
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _key.ExportSubjectPublicKeyInfo();
        }
    }

    private ECDsaP521Verifier(ECDsa key)
    {
        _key = key;
    }

    public static ECDsaP521Verifier FromPublicKey(byte[] spki)
    {
        ArgumentNullException.ThrowIfNull(spki);
        var key = ECDsa.Create();
        key.ImportSubjectPublicKeyInfo(spki, out _);
        return new ECDsaP521Verifier(key);
    }

    public static ECDsaP521Verifier FromPublicKeyPem(string pem)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pem);
        var key = ECDsa.Create();
        key.ImportFromPem(pem);
        return new ECDsaP521Verifier(key);
    }

    public bool Verify(byte[] data, byte[] signature)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(signature);
        return _key.VerifyData(data, signature, HashAlgorithmName.SHA512);
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _key.Dispose();
            _disposed = true;
        }
    }
}
