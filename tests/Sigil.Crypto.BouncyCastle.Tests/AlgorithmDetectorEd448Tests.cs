using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Sigil.Crypto.BouncyCastle.Tests;

public class AlgorithmDetectorEd448Tests
{
    [Fact]
    public void DetectFromSpki_Ed448_ReturnsEd448()
    {
        var generator = new Ed448KeyPairGenerator();
        generator.Init(new Ed448KeyGenerationParameters(new SecureRandom()));
        var keyPair = generator.GenerateKeyPair();

        var spkiInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public);
        var spki = spkiInfo.GetDerEncoded();

        var detected = AlgorithmDetector.DetectFromSpki(spki);
        Assert.Equal(SigningAlgorithm.Ed448, detected);
    }

    [Fact]
    public void DetectFromPkcs8_Ed448_ReturnsEd448()
    {
        var generator = new Ed448KeyPairGenerator();
        generator.Init(new Ed448KeyGenerationParameters(new SecureRandom()));
        var keyPair = generator.GenerateKeyPair();

        var pkcs8Info = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private);
        var pkcs8 = pkcs8Info.GetDerEncoded();

        var detected = AlgorithmDetector.DetectFromPkcs8Der(pkcs8);
        Assert.Equal(SigningAlgorithm.Ed448, detected);
    }
}
