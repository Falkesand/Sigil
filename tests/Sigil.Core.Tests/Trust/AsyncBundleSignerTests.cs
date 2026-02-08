using Sigil.Crypto;
using Sigil.Keys;
using Sigil.Trust;

namespace Sigil.Core.Tests.Trust;

public class AsyncBundleSignerTests
{
    [Fact]
    public async Task SignAsync_WithLocalSigner_ProducesSignedBundle()
    {
        using var signer = ECDsaP256Signer.Generate();
        var fingerprint = KeyFingerprint.Compute(signer.PublicKey);

        var bundle = new TrustBundle
        {
            Metadata = new BundleMetadata
            {
                Name = "test-bundle",
                Created = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ",
                    System.Globalization.CultureInfo.InvariantCulture)
            },
            Keys = [new TrustedKeyEntry { Fingerprint = fingerprint.Value, DisplayName = "test-key" }]
        };

        var result = await BundleSigner.SignAsync(bundle, signer);

        Assert.True(result.IsSuccess);
        Assert.NotNull(result.Value.Signature);
        Assert.Equal(fingerprint.Value, result.Value.Signature!.KeyId);
        Assert.Equal("ecdsa-p256", result.Value.Signature.Algorithm);
    }

    [Fact]
    public async Task SignAsync_ProducesVerifiableBundle()
    {
        using var signer = ECDsaP256Signer.Generate();
        var fingerprint = KeyFingerprint.Compute(signer.PublicKey);

        var bundle = new TrustBundle
        {
            Metadata = new BundleMetadata
            {
                Name = "verify-test",
                Created = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ",
                    System.Globalization.CultureInfo.InvariantCulture)
            },
            Keys = [new TrustedKeyEntry { Fingerprint = fingerprint.Value, DisplayName = "authority" }]
        };

        var signResult = await BundleSigner.SignAsync(bundle, signer);
        Assert.True(signResult.IsSuccess);

        var serializeResult = BundleSigner.Serialize(signResult.Value);
        Assert.True(serializeResult.IsSuccess);

        var verifyResult = BundleSigner.Verify(serializeResult.Value, fingerprint.Value);
        Assert.True(verifyResult.IsSuccess);
        Assert.True(verifyResult.Value);
    }

    [Fact]
    public async Task SignAsync_WithCancellationToken_Completes()
    {
        using var signer = ECDsaP256Signer.Generate();
        var fingerprint = KeyFingerprint.Compute(signer.PublicKey);
        using var cts = new CancellationTokenSource();

        var bundle = new TrustBundle
        {
            Metadata = new BundleMetadata
            {
                Name = "cancel-test",
                Created = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ",
                    System.Globalization.CultureInfo.InvariantCulture)
            },
            Keys = [new TrustedKeyEntry { Fingerprint = fingerprint.Value }]
        };

        var result = await BundleSigner.SignAsync(bundle, signer, cts.Token);

        Assert.True(result.IsSuccess);
        Assert.NotNull(result.Value.Signature);
    }
}
