using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Sigil.Crypto;
using Sigil.Keys;

namespace Sigil.Core.Tests.Keys;

public sealed class CertificateKeySignerTests : IDisposable
{
    private readonly List<IDisposable> _disposables = [];

    public void Dispose()
    {
        foreach (var d in _disposables)
            d.Dispose();
    }

    [Fact]
    public void Create_WithEcdsaP256Cert_ReturnsCorrectAlgorithm()
    {
        var cert = CreateSelfSignedCert(ECCurve.NamedCurves.nistP256);
        _disposables.Add(cert);

        using var signer = CertificateKeySigner.Create(cert);

        Assert.Equal(SigningAlgorithm.ECDsaP256, signer.Algorithm);
    }

    [Fact]
    public void Create_WithEcdsaP384Cert_ReturnsCorrectAlgorithm()
    {
        var cert = CreateSelfSignedCert(ECCurve.NamedCurves.nistP384);
        _disposables.Add(cert);

        using var signer = CertificateKeySigner.Create(cert);

        Assert.Equal(SigningAlgorithm.ECDsaP384, signer.Algorithm);
    }

    [Fact]
    public void Create_WithRsaCert_ReturnsCorrectAlgorithm()
    {
        var cert = CreateSelfSignedRsaCert();
        _disposables.Add(cert);

        using var signer = CertificateKeySigner.Create(cert);

        Assert.Equal(SigningAlgorithm.Rsa, signer.Algorithm);
    }

    [Fact]
    public void SignAndVerify_EcdsaP256_RoundTrip()
    {
        var cert = CreateSelfSignedCert(ECCurve.NamedCurves.nistP256);
        _disposables.Add(cert);
        var data = Encoding.UTF8.GetBytes("cert-signer-round-trip");

        using var signer = CertificateKeySigner.Create(cert);
        var signature = signer.Sign(data);

        using var verifier = VerifierFactory.CreateFromPublicKey(
            signer.PublicKey, signer.Algorithm.ToCanonicalName());
        Assert.True(verifier.Verify(data, signature));
    }

    [Fact]
    public void SignAndVerify_EcdsaP384_RoundTrip()
    {
        var cert = CreateSelfSignedCert(ECCurve.NamedCurves.nistP384);
        _disposables.Add(cert);
        var data = Encoding.UTF8.GetBytes("cert-signer-p384-round-trip");

        using var signer = CertificateKeySigner.Create(cert);
        var signature = signer.Sign(data);

        using var verifier = VerifierFactory.CreateFromPublicKey(
            signer.PublicKey, signer.Algorithm.ToCanonicalName());
        Assert.True(verifier.Verify(data, signature));
    }

    [Fact]
    public void SignAndVerify_EcdsaP521_RoundTrip()
    {
        var cert = CreateSelfSignedCert(ECCurve.NamedCurves.nistP521);
        _disposables.Add(cert);
        var data = Encoding.UTF8.GetBytes("cert-signer-p521-round-trip");

        using var signer = CertificateKeySigner.Create(cert);
        var signature = signer.Sign(data);

        using var verifier = VerifierFactory.CreateFromPublicKey(
            signer.PublicKey, signer.Algorithm.ToCanonicalName());
        Assert.True(verifier.Verify(data, signature));
    }

    [Fact]
    public void SignAndVerify_Rsa_RoundTrip()
    {
        var cert = CreateSelfSignedRsaCert();
        _disposables.Add(cert);
        var data = Encoding.UTF8.GetBytes("cert-signer-rsa-round-trip");

        using var signer = CertificateKeySigner.Create(cert);
        var signature = signer.Sign(data);

        using var verifier = VerifierFactory.CreateFromPublicKey(
            signer.PublicKey, signer.Algorithm.ToCanonicalName());
        Assert.True(verifier.Verify(data, signature));
    }

    [Fact]
    public void CanExportPrivateKey_ReturnsFalse()
    {
        var cert = CreateSelfSignedCert(ECCurve.NamedCurves.nistP256);
        _disposables.Add(cert);

        using var signer = CertificateKeySigner.Create(cert);

        Assert.False(signer.CanExportPrivateKey);
    }

    [Fact]
    public void ExportPrivateKeyPemBytes_ThrowsNotSupportedException()
    {
        var cert = CreateSelfSignedCert(ECCurve.NamedCurves.nistP256);
        _disposables.Add(cert);

        using var signer = CertificateKeySigner.Create(cert);

        Assert.Throws<NotSupportedException>(() => signer.ExportPrivateKeyPemBytes());
    }

    [Fact]
    public void ExportEncryptedPrivateKeyPemBytes_ThrowsNotSupportedException()
    {
        var cert = CreateSelfSignedCert(ECCurve.NamedCurves.nistP256);
        _disposables.Add(cert);

        using var signer = CertificateKeySigner.Create(cert);

        Assert.Throws<NotSupportedException>(
            () => signer.ExportEncryptedPrivateKeyPemBytes("password"));
    }

    [Fact]
    public void Create_CertWithoutPrivateKey_ThrowsArgumentException()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=Test", ecdsa, HashAlgorithmName.SHA256);
        using var certWithKey = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(1));

        // Export only public cert (no private key)
        var certBytes = certWithKey.Export(X509ContentType.Cert);
        using var certPublicOnly = X509CertificateLoader.LoadCertificate(certBytes);

        Assert.Throws<ArgumentException>(() => CertificateKeySigner.Create(certPublicOnly));
    }

    [Fact]
    public void PublicKey_IsValidSpki()
    {
        var cert = CreateSelfSignedCert(ECCurve.NamedCurves.nistP256);
        _disposables.Add(cert);

        using var signer = CertificateKeySigner.Create(cert);
        var spki = signer.PublicKey;

        // Should be importable
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportSubjectPublicKeyInfo(spki, out _);
    }

    private static X509Certificate2 CreateSelfSignedCert(ECCurve curve)
    {
        using var ecdsa = ECDsa.Create(curve);
        var req = new CertificateRequest("CN=Test", ecdsa, HashAlgorithmName.SHA256);
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(1));
        // Re-import with ephemeral key set to ensure private key is accessible
        return X509CertificateLoader.LoadPkcs12(
            cert.Export(X509ContentType.Pfx, ""),
            "",
            X509KeyStorageFlags.EphemeralKeySet);
    }

    private static X509Certificate2 CreateSelfSignedRsaCert()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(1));
        return X509CertificateLoader.LoadPkcs12(
            cert.Export(X509ContentType.Pfx, ""),
            "",
            X509KeyStorageFlags.EphemeralKeySet);
    }
}
