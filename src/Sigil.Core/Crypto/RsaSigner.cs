using System.Security.Cryptography;
using System.Text;

namespace Sigil.Crypto;

/// <summary>
/// Signs data using RSA-PSS with SHA-256. Default key size is 3072 bits.
/// BCL-only implementation — no external dependencies.
/// </summary>
public sealed class RsaSigner : ISigner
{
    private const int DefaultKeySize = 3072;
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

    private RsaSigner(RSA key)
    {
        _key = key;
    }

    public static RsaSigner Generate(int keySize = DefaultKeySize)
    {
        var key = RSA.Create(keySize);
        return new RsaSigner(key);
    }

    public static RsaSigner FromPkcs8(byte[] pkcs8)
    {
        var key = RSA.Create();
        key.ImportPkcs8PrivateKey(pkcs8, out _);
        return new RsaSigner(key);
    }

    public static RsaSigner FromEncryptedPkcs8(byte[] encryptedPkcs8, ReadOnlySpan<char> password)
    {
        var key = RSA.Create();
        key.ImportEncryptedPkcs8PrivateKey(password, encryptedPkcs8, out _);
        return new RsaSigner(key);
    }

    public static RsaSigner FromPem(ReadOnlySpan<char> pem)
    {
        if (pem.IsEmpty || pem.IsWhiteSpace())
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(pem));
        var key = RSA.Create();
        key.ImportFromPem(pem);
        return new RsaSigner(key);
    }

    public static RsaSigner FromEncryptedPem(ReadOnlySpan<char> pem, ReadOnlySpan<char> passphrase)
    {
        if (pem.IsEmpty || pem.IsWhiteSpace())
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(pem));
        if (passphrase.IsEmpty || passphrase.IsWhiteSpace())
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(passphrase));
        var key = RSA.Create();
        key.ImportFromEncryptedPem(pem, passphrase);
        return new RsaSigner(key);
    }

    public byte[] Sign(byte[] data)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(data);
        return _key.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
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

    public byte[] ExportPrivateKeyPemBytes()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return Encoding.UTF8.GetBytes(_key.ExportPkcs8PrivateKeyPem());
    }

    public byte[] ExportEncryptedPrivateKeyPemBytes(ReadOnlySpan<char> password)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var pbeParameters = new PbeParameters(
            PbeEncryptionAlgorithm.Aes256Cbc,
            HashAlgorithmName.SHA256,
            100_000);
        return Encoding.UTF8.GetBytes(_key.ExportEncryptedPkcs8PrivateKeyPem(password, pbeParameters));
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
