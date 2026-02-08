#pragma warning disable SYSLIB5006

using System.Security.Cryptography;
using System.Text;

namespace Sigil.Crypto;

/// <summary>
/// Signs data using ML-DSA-65 (FIPS 204).
/// Post-quantum lattice-based signature algorithm — NIST security category 3.
/// </summary>
public sealed class MLDsa65Signer : ISigner
{
    private static readonly byte[] EmptyContext = [];

    private readonly MLDsa _key;
    private bool _disposed;

    public SigningAlgorithm Algorithm => SigningAlgorithm.MLDsa65;

    public byte[] PublicKey
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _key.ExportSubjectPublicKeyInfo();
        }
    }

    private MLDsa65Signer(MLDsa key)
    {
        _key = key;
    }

    public static MLDsa65Signer Generate()
    {
        if (!MLDsa.IsSupported)
            throw new PlatformNotSupportedException("ML-DSA is not supported on this platform.");
        return new MLDsa65Signer(MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65));
    }

    public static MLDsa65Signer FromPem(ReadOnlySpan<char> pem)
    {
        if (pem.IsEmpty || pem.IsWhiteSpace())
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(pem));
        if (!MLDsa.IsSupported)
            throw new PlatformNotSupportedException("ML-DSA is not supported on this platform.");
        return new MLDsa65Signer(MLDsa.ImportFromPem(pem));
    }

    public static MLDsa65Signer FromEncryptedPem(ReadOnlySpan<char> pem, ReadOnlySpan<char> passphrase)
    {
        if (pem.IsEmpty || pem.IsWhiteSpace())
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(pem));
        if (passphrase.IsEmpty || passphrase.IsWhiteSpace())
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(passphrase));
        if (!MLDsa.IsSupported)
            throw new PlatformNotSupportedException("ML-DSA is not supported on this platform.");
        return new MLDsa65Signer(MLDsa.ImportFromEncryptedPem(pem, passphrase));
    }

    public byte[] Sign(byte[] data)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(data);
        return _key.SignData(data, EmptyContext);
    }

    public string ExportPublicKeyPem()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _key.ExportSubjectPublicKeyInfoPem();
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

    public ValueTask<byte[]> SignAsync(byte[] data, CancellationToken cancellationToken = default)
        => new(Sign(data));

    public bool CanExportPrivateKey => true;

    public void Dispose()
    {
        if (!_disposed)
        {
            _key.Dispose();
            _disposed = true;
        }
    }
}
