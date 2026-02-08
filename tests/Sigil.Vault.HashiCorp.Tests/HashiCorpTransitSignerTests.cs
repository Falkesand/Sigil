using System.Security.Cryptography;
using Sigil.Crypto;
using Sigil.Vault.HashiCorp;
using VaultSharp;

namespace Sigil.Vault.HashiCorp.Tests;

public class HashiCorpTransitSignerTests
{
    private static (byte[] PublicKey, HashiCorpTransitSigner Signer) CreateTestSigner(
        SigningAlgorithm algorithm = SigningAlgorithm.ECDsaP256)
    {
        // Generate a real ECDSA P-256 key pair for public key bytes.
        // We only need the SPKI bytes; the signer will not actually call Vault in property tests.
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = ecdsa.ExportSubjectPublicKeyInfo();

        // Pass null-forgiving for IVaultClient since we won't invoke SignAsync in these tests.
        var signer = new HashiCorpTransitSigner(
            null!,
            "test-key",
            "transit",
            algorithm,
            publicKey);

        return (publicKey, signer);
    }

    [Fact]
    public void Algorithm_ReturnsConstructorValue()
    {
        var (_, signer) = CreateTestSigner(SigningAlgorithm.ECDsaP256);
        using (signer)
        {
            Assert.Equal(SigningAlgorithm.ECDsaP256, signer.Algorithm);
        }
    }

    [Theory]
    [InlineData(SigningAlgorithm.ECDsaP256)]
    [InlineData(SigningAlgorithm.ECDsaP384)]
    [InlineData(SigningAlgorithm.Rsa)]
    public void Algorithm_ReturnsCorrectValue_ForEachSupportedType(SigningAlgorithm algorithm)
    {
        var (_, signer) = CreateTestSigner(algorithm);
        using (signer)
        {
            Assert.Equal(algorithm, signer.Algorithm);
        }
    }

    [Fact]
    public void PublicKey_ReturnsConstructorValue()
    {
        var (publicKey, signer) = CreateTestSigner();
        using (signer)
        {
            Assert.Equal(publicKey, signer.PublicKey);
        }
    }

    [Fact]
    public void PublicKey_IsNonEmpty()
    {
        var (_, signer) = CreateTestSigner();
        using (signer)
        {
            Assert.True(signer.PublicKey.Length > 0);
        }
    }

    [Fact]
    public void CanExportPrivateKey_ReturnsFalse()
    {
        var (_, signer) = CreateTestSigner();
        using (signer)
        {
            Assert.False(signer.CanExportPrivateKey);
        }
    }

    [Fact]
    public void Sign_ThrowsNotSupportedException()
    {
        var (_, signer) = CreateTestSigner();
        using (signer)
        {
            Assert.Throws<NotSupportedException>(() => signer.Sign(new byte[] { 1, 2, 3 }));
        }
    }

    [Fact]
    public void ExportPrivateKeyPemBytes_ThrowsNotSupportedException()
    {
        var (_, signer) = CreateTestSigner();
        using (signer)
        {
            Assert.Throws<NotSupportedException>(() => signer.ExportPrivateKeyPemBytes());
        }
    }

    [Fact]
    public void ExportEncryptedPrivateKeyPemBytes_ThrowsNotSupportedException()
    {
        var (_, signer) = CreateTestSigner();
        using (signer)
        {
            Assert.Throws<NotSupportedException>(() => signer.ExportEncryptedPrivateKeyPemBytes("password"));
        }
    }

    [Fact]
    public void ExportPublicKeyPem_ReturnsValidPemFormat()
    {
        var (_, signer) = CreateTestSigner();
        using (signer)
        {
            var pem = signer.ExportPublicKeyPem();

            Assert.StartsWith("-----BEGIN PUBLIC KEY-----", pem);
            Assert.Contains("-----END PUBLIC KEY-----", pem);
        }
    }

    [Fact]
    public void ExportPublicKeyPem_CanBeReimported()
    {
        var (publicKey, signer) = CreateTestSigner();
        using (signer)
        {
            var pem = signer.ExportPublicKeyPem();

            // Reimport the PEM and verify it matches the original SPKI bytes
            using var reimported = ECDsa.Create();
            reimported.ImportFromPem(pem);
            var reimportedSpki = reimported.ExportSubjectPublicKeyInfo();

            Assert.Equal(publicKey, reimportedSpki);
        }
    }

    [Fact]
    public void Dispose_DoesNotThrow()
    {
        var (_, signer) = CreateTestSigner();

        var ex = Record.Exception(() => signer.Dispose());

        Assert.Null(ex);
    }

    [Fact]
    public void Dispose_CanBeCalledMultipleTimes()
    {
        var (_, signer) = CreateTestSigner();

        var ex = Record.Exception(() =>
        {
            signer.Dispose();
            signer.Dispose();
        });

        Assert.Null(ex);
    }

    [Fact]
    public void ImplementsISigner()
    {
        var (_, signer) = CreateTestSigner();
        using (signer)
        {
            Assert.IsAssignableFrom<ISigner>(signer);
        }
    }

    [Fact]
    public void InheritsFromVaultSignerBase()
    {
        var (_, signer) = CreateTestSigner();
        using (signer)
        {
            Assert.IsAssignableFrom<VaultSignerBase>(signer);
        }
    }

    [Fact]
    public async Task SignAsync_NullData_ThrowsArgumentNullException()
    {
        var (_, signer) = CreateTestSigner();
        using (signer)
        {
            // SignAsync calls ArgumentNullException.ThrowIfNull(data)
            await Assert.ThrowsAsync<ArgumentNullException>(
                async () => await signer.SignAsync(null!, CancellationToken.None));
        }
    }
}
