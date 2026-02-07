using System.Security.Cryptography;

namespace Sigil.Crypto;

/// <summary>
/// Verifies RSA-PSS SHA-256 signatures. BCL-only, no external dependencies.
/// </summary>
public sealed class RsaVerifier : IVerifier
{
    private readonly RSA _key;
    private bool _disposed;

    public SigningAlgorithm Algorithm => SigningAlgorithm.Rsa;

    public byte[] PublicKey
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _key.ExportSubjectPublicKeyInfo();
        }
    }

    private RsaVerifier(RSA key)
    {
        _key = key;
    }

    public static RsaVerifier FromPublicKey(byte[] spki)
    {
        ArgumentNullException.ThrowIfNull(spki);
        var key = RSA.Create();
        key.ImportSubjectPublicKeyInfo(spki, out _);
        return new RsaVerifier(key);
    }

    public static RsaVerifier FromPublicKeyPem(string pem)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pem);
        var key = RSA.Create();
        key.ImportFromPem(pem);
        return new RsaVerifier(key);
    }

    public bool Verify(byte[] data, byte[] signature)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(signature);
        return _key.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
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
