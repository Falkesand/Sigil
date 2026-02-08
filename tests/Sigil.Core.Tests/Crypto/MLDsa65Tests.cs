#pragma warning disable SYSLIB5006

using System.Security.Cryptography;
using System.Text;
using Sigil.Crypto;

namespace Sigil.Core.Tests.Crypto;

public class MLDsa65Tests
{
    [Fact]
    public void SigningAlgorithm_MLDsa65_RoundTrips_CanonicalName()
    {
        var name = SigningAlgorithm.MLDsa65.ToCanonicalName();
        Assert.Equal("ml-dsa-65", name);

        var parsed = SigningAlgorithmExtensions.ParseAlgorithm(name);
        Assert.Equal(SigningAlgorithm.MLDsa65, parsed);
    }

    [Fact]
    public void Generate_ProducesValidSigner()
    {
        if (!MLDsa.IsSupported) return;

        using var signer = MLDsa65Signer.Generate();
        Assert.Equal(SigningAlgorithm.MLDsa65, signer.Algorithm);
        Assert.NotNull(signer.PublicKey);
        Assert.True(signer.PublicKey.Length > 0);
    }

    [Fact]
    public void SignAndVerify_RoundTrip_Succeeds()
    {
        if (!MLDsa.IsSupported) return;

        using var signer = MLDsa65Signer.Generate();
        var data = Encoding.UTF8.GetBytes("test message for ML-DSA signing");

        var signature = signer.Sign(data);
        Assert.NotNull(signature);

        using var verifier = MLDsa65Verifier.FromPublicKey(signer.PublicKey);
        Assert.True(verifier.Verify(data, signature));
    }

    [Fact]
    public void Verify_TamperedData_Fails()
    {
        if (!MLDsa.IsSupported) return;

        using var signer = MLDsa65Signer.Generate();
        var data = Encoding.UTF8.GetBytes("original message");
        var signature = signer.Sign(data);

        var tampered = Encoding.UTF8.GetBytes("tampered message");
        using var verifier = MLDsa65Verifier.FromPublicKey(signer.PublicKey);
        Assert.False(verifier.Verify(tampered, signature));
    }

    [Fact]
    public void Verify_WrongKey_Fails()
    {
        if (!MLDsa.IsSupported) return;

        using var signer1 = MLDsa65Signer.Generate();
        using var signer2 = MLDsa65Signer.Generate();
        var data = Encoding.UTF8.GetBytes("message signed by key 1");
        var signature = signer1.Sign(data);

        using var verifierWithKey2 = MLDsa65Verifier.FromPublicKey(signer2.PublicKey);
        Assert.False(verifierWithKey2.Verify(data, signature));
    }

    [Fact]
    public void ExportImport_PublicKeyPem_RoundTrip()
    {
        if (!MLDsa.IsSupported) return;

        using var signer = MLDsa65Signer.Generate();
        var pem = signer.ExportPublicKeyPem();

        Assert.Contains("BEGIN PUBLIC KEY", pem);
        Assert.Contains("END PUBLIC KEY", pem);

        using var verifier = MLDsa65Verifier.FromPublicKeyPem(pem);
        var data = Encoding.UTF8.GetBytes("PEM round trip");
        var signature = signer.Sign(data);
        Assert.True(verifier.Verify(data, signature));
    }

    [Fact]
    public void ExportImport_PrivateKeyPem_RoundTrip()
    {
        if (!MLDsa.IsSupported) return;

        using var original = MLDsa65Signer.Generate();
        var data = Encoding.UTF8.GetBytes("private key PEM round trip");

        var pemBytes = original.ExportPrivateKeyPemBytes();
        var pemString = Encoding.UTF8.GetString(pemBytes);
        Assert.Contains("BEGIN PRIVATE KEY", pemString);

        using var restored = MLDsa65Signer.FromPem(pemString);
        using var verifier = MLDsa65Verifier.FromPublicKey(original.PublicKey);
        var signature = restored.Sign(data);
        Assert.True(verifier.Verify(data, signature));
    }

    [Fact]
    public void ExportImport_EncryptedPrivateKeyPem_RoundTrip()
    {
        if (!MLDsa.IsSupported) return;

        using var original = MLDsa65Signer.Generate();
        var data = Encoding.UTF8.GetBytes("encrypted PEM round trip");
        var password = "test-passphrase-123";

        var encryptedPemBytes = original.ExportEncryptedPrivateKeyPemBytes(password);
        var pemString = Encoding.UTF8.GetString(encryptedPemBytes);
        Assert.Contains("ENCRYPTED", pemString);

        using var restored = MLDsa65Signer.FromEncryptedPem(pemString, password);
        using var verifier = MLDsa65Verifier.FromPublicKey(original.PublicKey);
        var signature = restored.Sign(data);
        Assert.True(verifier.Verify(data, signature));
    }

    [Fact]
    public void SignerFactory_Generates_MLDsa65()
    {
        if (!MLDsa.IsSupported) return;

        using var signer = SignerFactory.Generate(SigningAlgorithm.MLDsa65);
        Assert.Equal(SigningAlgorithm.MLDsa65, signer.Algorithm);
    }

    [Fact]
    public void VerifierFactory_Creates_FromSpki()
    {
        if (!MLDsa.IsSupported) return;

        using var signer = MLDsa65Signer.Generate();
        using var verifier = VerifierFactory.CreateFromPublicKey(signer.PublicKey, "ml-dsa-65");
        Assert.Equal(SigningAlgorithm.MLDsa65, verifier.Algorithm);
    }

    [Fact]
    public void AlgorithmDetector_DetectsMLDsa65_FromSpki()
    {
        if (!MLDsa.IsSupported) return;

        using var key = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        var spki = key.ExportSubjectPublicKeyInfo();

        var detected = AlgorithmDetector.DetectFromSpki(spki);
        Assert.Equal(SigningAlgorithm.MLDsa65, detected);
    }

    [Fact]
    public void Dispose_PreventsFurtherUse()
    {
        if (!MLDsa.IsSupported) return;

        var signer = MLDsa65Signer.Generate();
        signer.Dispose();

        Assert.Throws<ObjectDisposedException>(() => signer.Sign([]));
    }
}
