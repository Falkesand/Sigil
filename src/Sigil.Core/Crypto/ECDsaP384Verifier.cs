using System.Security.Cryptography;

namespace Sigil.Crypto;

/// <summary>
/// Verifies ECDSA P-384 signatures. BCL-only, no external dependencies.
/// </summary>
public sealed class ECDsaP384Verifier : IVerifier
{
    private readonly ECDsa _key;
    private bool _disposed;

    public SigningAlgorithm Algorithm => SigningAlgorithm.ECDsaP384;

    public byte[] PublicKey
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _key.ExportSubjectPublicKeyInfo();
        }
    }

    private ECDsaP384Verifier(ECDsa key)
    {
        _key = key;
    }

    public static ECDsaP384Verifier FromPublicKey(byte[] spki)
    {
        ArgumentNullException.ThrowIfNull(spki);
        var key = ECDsa.Create();
        key.ImportSubjectPublicKeyInfo(spki, out _);
        return new ECDsaP384Verifier(key);
    }

    public static ECDsaP384Verifier FromPublicKeyPem(string pem)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pem);
        var key = ECDsa.Create();
        key.ImportFromPem(pem);
        return new ECDsaP384Verifier(key);
    }

    public bool Verify(byte[] data, byte[] signature)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(signature);
        return _key.VerifyData(data, signature, HashAlgorithmName.SHA384);
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
