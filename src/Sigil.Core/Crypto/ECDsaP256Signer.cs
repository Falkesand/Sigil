using System.Security.Cryptography;

namespace Sigil.Crypto;

/// <summary>
/// Signs data using ECDSA with the NIST P-256 curve.
/// BCL-only implementation — no external dependencies.
/// Will be swapped to Ed25519 when the native static API ships in a future .NET SDK.
/// </summary>
public sealed class ECDsaP256Signer : ISigner
{
    private readonly ECDsa _key;
    private bool _disposed;

    public SigningAlgorithm Algorithm => SigningAlgorithm.ECDsaP256;

    public byte[] PublicKey
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _key.ExportSubjectPublicKeyInfo();
        }
    }

    private ECDsaP256Signer(ECDsa key)
    {
        _key = key;
    }

    public static ECDsaP256Signer Generate()
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return new ECDsaP256Signer(key);
    }

    public static ECDsaP256Signer FromPkcs8(byte[] pkcs8)
    {
        var key = ECDsa.Create();
        key.ImportPkcs8PrivateKey(pkcs8, out _);
        return new ECDsaP256Signer(key);
    }

    public static ECDsaP256Signer FromEncryptedPkcs8(byte[] encryptedPkcs8, ReadOnlySpan<char> password)
    {
        var key = ECDsa.Create();
        key.ImportEncryptedPkcs8PrivateKey(password, encryptedPkcs8, out _);
        return new ECDsaP256Signer(key);
    }

    public static ECDsaP256Signer FromPem(string pem)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pem);
        var key = ECDsa.Create();
        key.ImportFromPem(pem);
        return new ECDsaP256Signer(key);
    }

    public static ECDsaP256Signer FromEncryptedPem(string pem, string passphrase)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pem);
        ArgumentException.ThrowIfNullOrWhiteSpace(passphrase);
        var key = ECDsa.Create();
        key.ImportFromEncryptedPem(pem, passphrase);
        return new ECDsaP256Signer(key);
    }

    public byte[] Sign(byte[] data)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(data);
        return _key.SignData(data, HashAlgorithmName.SHA256);
    }

    public byte[] ExportPkcs8()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _key.ExportPkcs8PrivateKey();
    }

    public byte[] ExportEncryptedPkcs8(ReadOnlySpan<char> password)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var pbeParameters = new PbeParameters(
            PbeEncryptionAlgorithm.Aes256Cbc,
            HashAlgorithmName.SHA256,
            100_000);
        return _key.ExportEncryptedPkcs8PrivateKey(password, pbeParameters);
    }

    public string ExportPublicKeyPem()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _key.ExportSubjectPublicKeyInfoPem();
    }

    public string ExportPrivateKeyPem()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _key.ExportPkcs8PrivateKeyPem();
    }

    public string ExportEncryptedPrivateKeyPem(ReadOnlySpan<char> password)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var pbeParameters = new PbeParameters(
            PbeEncryptionAlgorithm.Aes256Cbc,
            HashAlgorithmName.SHA256,
            100_000);
        return _key.ExportEncryptedPkcs8PrivateKeyPem(password, pbeParameters);
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
