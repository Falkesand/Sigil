using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Sigil.Crypto;

namespace Sigil.Keys;

/// <summary>
/// ISigner implementation for certificate-backed keys (e.g., from the Windows Certificate Store
/// or CNG/HSM-backed certificates). The private key may be non-exportable.
/// Signing is synchronous — certificate store keys sign locally via CNG.
/// Does NOT own or dispose the certificate; the caller manages the certificate lifetime.
/// </summary>
public sealed class CertificateKeySigner : ISigner
{
    private readonly AsymmetricAlgorithm _privateKey;
    private readonly SigningAlgorithm _algorithm;
    private readonly byte[] _publicKeySpki;
    private bool _disposed;

    public SigningAlgorithm Algorithm => _algorithm;
    public byte[] PublicKey => _publicKeySpki;
    public bool CanExportPrivateKey => false;

    private CertificateKeySigner(AsymmetricAlgorithm privateKey, SigningAlgorithm algorithm, byte[] publicKeySpki)
    {
        _privateKey = privateKey;
        _algorithm = algorithm;
        _publicKeySpki = publicKeySpki;
    }

    public static CertificateKeySigner Create(X509Certificate2 cert)
    {
        ArgumentNullException.ThrowIfNull(cert);

        if (!cert.HasPrivateKey)
            throw new ArgumentException("Certificate does not contain a private key.", nameof(cert));

        // Try ECDsa first (most common for code signing)
        var ecKey = cert.GetECDsaPrivateKey();
        if (ecKey is not null)
        {
            var parameters = ecKey.ExportParameters(false);
            var curveName = parameters.Curve.Oid?.FriendlyName;
            var algorithm = curveName switch
            {
                "ECDSA_P256" or "nistP256" => SigningAlgorithm.ECDsaP256,
                "ECDSA_P384" or "nistP384" => SigningAlgorithm.ECDsaP384,
                "ECDSA_P521" or "nistP521" => SigningAlgorithm.ECDsaP521,
                _ => throw new NotSupportedException($"Unsupported EC curve: {curveName}")
            };
            var spki = ecKey.ExportSubjectPublicKeyInfo();
            return new CertificateKeySigner(ecKey, algorithm, spki);
        }

        // Try RSA
        var rsaKey = cert.GetRSAPrivateKey();
        if (rsaKey is not null)
        {
            var spki = rsaKey.ExportSubjectPublicKeyInfo();
            return new CertificateKeySigner(rsaKey, SigningAlgorithm.Rsa, spki);
        }

        throw new NotSupportedException(
            "Certificate private key algorithm is not supported. Supported: ECDSA (P-256, P-384, P-521), RSA.");
    }

    public byte[] Sign(byte[] data)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(data);

        return _algorithm switch
        {
            SigningAlgorithm.ECDsaP256 =>
                ((ECDsa)_privateKey).SignData(data, HashAlgorithmName.SHA256),
            SigningAlgorithm.ECDsaP384 =>
                ((ECDsa)_privateKey).SignData(data, HashAlgorithmName.SHA384),
            SigningAlgorithm.ECDsaP521 =>
                ((ECDsa)_privateKey).SignData(data, HashAlgorithmName.SHA512),
            SigningAlgorithm.Rsa =>
                ((RSA)_privateKey).SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss),
            _ => throw new NotSupportedException($"Unsupported algorithm: {_algorithm}")
        };
    }

    public string ExportPublicKeyPem()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var base64 = Convert.ToBase64String(_publicKeySpki);
        var sb = new System.Text.StringBuilder();
        sb.AppendLine("-----BEGIN PUBLIC KEY-----");
        for (int i = 0; i < base64.Length; i += 64)
        {
            int len = Math.Min(64, base64.Length - i);
            sb.AppendLine(base64.Substring(i, len));
        }
        sb.Append("-----END PUBLIC KEY-----");
        return sb.ToString();
    }

    public byte[] ExportPrivateKeyPemBytes() =>
        throw new NotSupportedException("Certificate-backed signers do not export private key material.");

    public byte[] ExportEncryptedPrivateKeyPemBytes(ReadOnlySpan<char> password) =>
        throw new NotSupportedException("Certificate-backed signers do not export private key material.");

    public ValueTask<byte[]> SignAsync(byte[] data, CancellationToken cancellationToken = default)
        => new(Sign(data));

    public void Dispose()
    {
        if (!_disposed)
        {
            // We do NOT dispose _privateKey — it's owned by the X509Certificate2
            _disposed = true;
        }
    }
}
