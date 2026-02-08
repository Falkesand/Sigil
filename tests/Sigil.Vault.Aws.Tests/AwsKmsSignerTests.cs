using System.Security.Cryptography;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using Sigil.Crypto;
using Sigil.Vault.Aws;

namespace Sigil.Vault.Aws.Tests;

public class AwsKmsSignerTests
{
    private static (byte[] PublicKey, AwsKmsSigner Signer) CreateTestSigner(
        SigningAlgorithm algorithm = SigningAlgorithm.ECDsaP256,
        FakeKmsClient? client = null)
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = ecdsa.ExportSubjectPublicKeyInfo();

        var signer = new AwsKmsSigner(
            client ?? new FakeKmsClient(),
            "test-key-id",
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

            using var reimported = ECDsa.Create();
            reimported.ImportFromPem(pem);
            var reimportedSpki = reimported.ExportSubjectPublicKeyInfo();

            Assert.Equal(publicKey, reimportedSpki);
        }
    }

    [Fact]
    public void Constructor_NullClient_ThrowsArgumentNullException()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = ecdsa.ExportSubjectPublicKeyInfo();

        var ex = Assert.Throws<ArgumentNullException>(
            () => new AwsKmsSigner(null!, "key-id", SigningAlgorithm.ECDsaP256, publicKey));

        Assert.Equal("client", ex.ParamName);
    }

    [Fact]
    public void Constructor_NullKeyId_ThrowsArgumentNullException()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = ecdsa.ExportSubjectPublicKeyInfo();

        var ex = Assert.Throws<ArgumentNullException>(
            () => new AwsKmsSigner(new FakeKmsClient(), null!, SigningAlgorithm.ECDsaP256, publicKey));

        Assert.Equal("keyId", ex.ParamName);
    }

    [Fact]
    public void Constructor_NullPublicKey_ThrowsArgumentNullException()
    {
        var ex = Assert.Throws<ArgumentNullException>(
            () => new AwsKmsSigner(new FakeKmsClient(), "key-id", SigningAlgorithm.ECDsaP256, null!));

        Assert.Equal("publicKey", ex.ParamName);
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
    public async Task SignAsync_CallsKmsClientWithCorrectParameters()
    {
        SignRequest? capturedRequest = null;
        var fakeSignature = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF };
        var client = new FakeKmsClient(
            signHandler: (request, _) =>
            {
                capturedRequest = request;
                var response = new SignResponse
                {
                    Signature = new MemoryStream(fakeSignature)
                };
                return Task.FromResult(response);
            });

        var (_, signer) = CreateTestSigner(SigningAlgorithm.ECDsaP256, client);
        using (signer)
        {
            var data = new byte[] { 1, 2, 3 };
            var signature = await signer.SignAsync(data);

            Assert.NotNull(capturedRequest);
            Assert.Equal("test-key-id", capturedRequest!.KeyId);
            Assert.Equal(MessageType.RAW, capturedRequest.MessageType);
            Assert.Equal(SigningAlgorithmSpec.ECDSA_SHA_256, capturedRequest.SigningAlgorithm);
            Assert.Equal(fakeSignature, signature);
        }
    }

    [Fact]
    public async Task SignAsync_ECDsaP384_UsesCorrectAwsAlgorithm()
    {
        SignRequest? capturedRequest = null;
        var client = new FakeKmsClient(
            signHandler: (request, _) =>
            {
                capturedRequest = request;
                return Task.FromResult(new SignResponse
                {
                    Signature = new MemoryStream(new byte[] { 1 })
                });
            });

        var (_, signer) = CreateTestSigner(SigningAlgorithm.ECDsaP384, client);
        using (signer)
        {
            await signer.SignAsync(new byte[] { 1 });

            Assert.NotNull(capturedRequest);
            Assert.Equal(SigningAlgorithmSpec.ECDSA_SHA_384, capturedRequest!.SigningAlgorithm);
        }
    }

    [Fact]
    public async Task SignAsync_Rsa_UsesCorrectAwsAlgorithm()
    {
        SignRequest? capturedRequest = null;
        var client = new FakeKmsClient(
            signHandler: (request, _) =>
            {
                capturedRequest = request;
                return Task.FromResult(new SignResponse
                {
                    Signature = new MemoryStream(new byte[] { 1 })
                });
            });

        var (_, signer) = CreateTestSigner(SigningAlgorithm.Rsa, client);
        using (signer)
        {
            await signer.SignAsync(new byte[] { 1 });

            Assert.NotNull(capturedRequest);
            Assert.Equal(SigningAlgorithmSpec.RSASSA_PSS_SHA_256, capturedRequest!.SigningAlgorithm);
        }
    }

    [Fact]
    public async Task SignAsync_ReturnsSignatureFromKmsResponse()
    {
        var expectedSignature = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 };
        var client = new FakeKmsClient(
            signHandler: (_, _) => Task.FromResult(new SignResponse
            {
                Signature = new MemoryStream(expectedSignature)
            }));

        var (_, signer) = CreateTestSigner(client: client);
        using (signer)
        {
            var result = await signer.SignAsync(new byte[] { 0xFF });

            Assert.Equal(expectedSignature, result);
        }
    }

    [Fact]
    public async Task SignAsync_PassesDataToKmsRequest()
    {
        byte[]? capturedData = null;
        var client = new FakeKmsClient(
            signHandler: (request, _) =>
            {
                capturedData = request.Message.ToArray();
                return Task.FromResult(new SignResponse
                {
                    Signature = new MemoryStream(new byte[] { 1 })
                });
            });

        var (_, signer) = CreateTestSigner(client: client);
        using (signer)
        {
            var data = new byte[] { 10, 20, 30, 40, 50 };
            await signer.SignAsync(data);

            Assert.NotNull(capturedData);
            Assert.Equal(new byte[] { 10, 20, 30, 40, 50 }, capturedData);
        }
    }
}
