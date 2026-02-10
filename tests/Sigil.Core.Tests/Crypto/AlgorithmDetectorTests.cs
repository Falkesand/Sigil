using System.Security.Cryptography;
using Sigil.Crypto;

namespace Sigil.Core.Tests.Crypto;

public class AlgorithmDetectorTests
{
    [Fact]
    public void DetectFromSpki_ECDsaP256_ReturnsCorrectAlgorithm()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var spki = key.ExportSubjectPublicKeyInfo();

        var detected = AlgorithmDetector.DetectFromSpki(spki);

        Assert.Equal(SigningAlgorithm.ECDsaP256, detected);
    }

    [Fact]
    public void DetectFromSpki_ECDsaP384_ReturnsCorrectAlgorithm()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var spki = key.ExportSubjectPublicKeyInfo();

        var detected = AlgorithmDetector.DetectFromSpki(spki);

        Assert.Equal(SigningAlgorithm.ECDsaP384, detected);
    }

    [Fact]
    public void DetectFromSpki_ECDsaP521_ReturnsCorrectAlgorithm()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP521);
        var spki = key.ExportSubjectPublicKeyInfo();

        var detected = AlgorithmDetector.DetectFromSpki(spki);

        Assert.Equal(SigningAlgorithm.ECDsaP521, detected);
    }

    [Fact]
    public void DetectFromSpki_Rsa_ReturnsCorrectAlgorithm()
    {
        using var key = RSA.Create(2048);
        var spki = key.ExportSubjectPublicKeyInfo();

        var detected = AlgorithmDetector.DetectFromSpki(spki);

        Assert.Equal(SigningAlgorithm.Rsa, detected);
    }

    [Fact]
    public void DetectFromSpki_NullInput_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => AlgorithmDetector.DetectFromSpki(null!));
    }

    [Fact]
    public void DetectFromSpki_EmptyInput_ThrowsNotSupportedException()
    {
        Assert.Throws<NotSupportedException>(() => AlgorithmDetector.DetectFromSpki([]));
    }

    [Fact]
    public void DetectFromPkcs8Der_ECDsaP256_ReturnsCorrectAlgorithm()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pkcs8 = key.ExportPkcs8PrivateKey();

        var detected = AlgorithmDetector.DetectFromPkcs8Der(pkcs8);

        Assert.Equal(SigningAlgorithm.ECDsaP256, detected);
    }

    [Fact]
    public void DetectFromPkcs8Der_ECDsaP384_ReturnsCorrectAlgorithm()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var pkcs8 = key.ExportPkcs8PrivateKey();

        var detected = AlgorithmDetector.DetectFromPkcs8Der(pkcs8);

        Assert.Equal(SigningAlgorithm.ECDsaP384, detected);
    }

    [Fact]
    public void DetectFromPkcs8Der_ECDsaP521_ReturnsCorrectAlgorithm()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP521);
        var pkcs8 = key.ExportPkcs8PrivateKey();

        var detected = AlgorithmDetector.DetectFromPkcs8Der(pkcs8);

        Assert.Equal(SigningAlgorithm.ECDsaP521, detected);
    }

    [Fact]
    public void DetectFromPkcs8Der_Rsa_ReturnsCorrectAlgorithm()
    {
        using var key = RSA.Create(2048);
        var pkcs8 = key.ExportPkcs8PrivateKey();

        var detected = AlgorithmDetector.DetectFromPkcs8Der(pkcs8);

        Assert.Equal(SigningAlgorithm.Rsa, detected);
    }

    [Fact]
    public void DetectFromPkcs8Der_NullInput_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => AlgorithmDetector.DetectFromPkcs8Der(null!));
    }
}
