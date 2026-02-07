using System.Text.Json;
using Sigil.Crypto;
using Sigil.Keys;
using Sigil.Trust;

namespace Sigil.Core.Tests.Trust;

public class BundleSignerTests : IDisposable
{
    private readonly ISigner _signer;
    private readonly KeyFingerprint _fingerprint;

    public BundleSignerTests()
    {
        _signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        _fingerprint = KeyFingerprint.Compute(_signer.PublicKey);
    }

    public void Dispose()
    {
        _signer.Dispose();
    }

    [Fact]
    public void Serialize_produces_valid_json()
    {
        var bundle = CreateTestBundle();

        var result = BundleSigner.Serialize(bundle);

        Assert.True(result.IsSuccess);
        var json = result.Value;
        Assert.Contains("\"version\"", json);
        Assert.Contains("\"kind\"", json);
        Assert.Contains("\"trust-bundle\"", json);
        Assert.Contains("\"test-bundle\"", json);
    }

    [Fact]
    public void Deserialize_round_trips()
    {
        var bundle = CreateTestBundle();
        var serializeResult = BundleSigner.Serialize(bundle);
        Assert.True(serializeResult.IsSuccess);

        var deserializeResult = BundleSigner.Deserialize(serializeResult.Value);

        Assert.True(deserializeResult.IsSuccess);
        Assert.Equal("1.0", deserializeResult.Value.Version);
        Assert.Equal("trust-bundle", deserializeResult.Value.Kind);
        Assert.Equal("test-bundle", deserializeResult.Value.Metadata.Name);
    }

    [Fact]
    public void Deserialize_invalid_json_returns_failure()
    {
        var result = BundleSigner.Deserialize("not valid json{{{");

        Assert.False(result.IsSuccess);
        Assert.Equal(TrustErrorKind.DeserializationFailed, result.ErrorKind);
    }

    [Fact]
    public void Sign_populates_signature_fields()
    {
        var bundle = CreateTestBundle();

        var result = BundleSigner.Sign(bundle, _signer);

        Assert.True(result.IsSuccess);
        var signed = result.Value;
        Assert.NotNull(signed.Signature);
        Assert.Equal(_fingerprint.Value, signed.Signature.KeyId);
        Assert.Equal("ecdsa-p256", signed.Signature.Algorithm);
        Assert.NotEmpty(signed.Signature.PublicKey);
        Assert.NotEmpty(signed.Signature.Value);
        Assert.NotEmpty(signed.Signature.Timestamp);
    }

    [Fact]
    public void Sign_preserves_bundle_content()
    {
        var bundle = CreateTestBundle();

        var result = BundleSigner.Sign(bundle, _signer);

        Assert.True(result.IsSuccess);
        var signed = result.Value;
        Assert.Equal("test-bundle", signed.Metadata.Name);
        Assert.Single(signed.Keys);
        Assert.Equal("sha256:abc123", signed.Keys[0].Fingerprint);
    }

    [Fact]
    public void Verify_valid_signature_succeeds()
    {
        var bundle = CreateTestBundle();
        var signResult = BundleSigner.Sign(bundle, _signer);
        Assert.True(signResult.IsSuccess);

        var serializeResult = BundleSigner.Serialize(signResult.Value);
        Assert.True(serializeResult.IsSuccess);

        var verifyResult = BundleSigner.Verify(serializeResult.Value, _fingerprint.Value);

        Assert.True(verifyResult.IsSuccess);
        Assert.True(verifyResult.Value);
    }

    [Fact]
    public void Verify_tampered_bundle_fails()
    {
        var bundle = CreateTestBundle();
        var signResult = BundleSigner.Sign(bundle, _signer);
        Assert.True(signResult.IsSuccess);

        var serializeResult = BundleSigner.Serialize(signResult.Value);
        Assert.True(serializeResult.IsSuccess);

        // Tamper with the JSON
        var tampered = serializeResult.Value.Replace("test-bundle", "hacked-bundle");

        var verifyResult = BundleSigner.Verify(tampered, _fingerprint.Value);

        Assert.True(verifyResult.IsSuccess);
        Assert.False(verifyResult.Value);
    }

    [Fact]
    public void Verify_wrong_authority_fails()
    {
        var bundle = CreateTestBundle();
        var signResult = BundleSigner.Sign(bundle, _signer);
        Assert.True(signResult.IsSuccess);

        var serializeResult = BundleSigner.Serialize(signResult.Value);
        Assert.True(serializeResult.IsSuccess);

        var wrongAuthority = "sha256:" + new string('0', 64);

        var verifyResult = BundleSigner.Verify(serializeResult.Value, wrongAuthority);

        Assert.False(verifyResult.IsSuccess);
        Assert.Equal(TrustErrorKind.AuthorityMismatch, verifyResult.ErrorKind);
    }

    [Fact]
    public void Verify_unsigned_bundle_fails()
    {
        var bundle = CreateTestBundle();
        var serializeResult = BundleSigner.Serialize(bundle);
        Assert.True(serializeResult.IsSuccess);

        var verifyResult = BundleSigner.Verify(serializeResult.Value, _fingerprint.Value);

        Assert.False(verifyResult.IsSuccess);
        Assert.Equal(TrustErrorKind.BundleInvalid, verifyResult.ErrorKind);
    }

    [Fact]
    public void Sign_with_different_algorithms()
    {
        using var rsaSigner = SignerFactory.Generate(SigningAlgorithm.Rsa);
        var bundle = CreateTestBundle();

        var result = BundleSigner.Sign(bundle, rsaSigner);

        Assert.True(result.IsSuccess);
        Assert.Equal("rsa-pss-sha256", result.Value.Signature!.Algorithm);
    }

    [Fact]
    public void Verify_with_rsa_signed_bundle()
    {
        using var rsaSigner = SignerFactory.Generate(SigningAlgorithm.Rsa);
        var rsaFingerprint = KeyFingerprint.Compute(rsaSigner.PublicKey);
        var bundle = CreateTestBundle();

        var signResult = BundleSigner.Sign(bundle, rsaSigner);
        Assert.True(signResult.IsSuccess);

        var serializeResult = BundleSigner.Serialize(signResult.Value);
        Assert.True(serializeResult.IsSuccess);

        var verifyResult = BundleSigner.Verify(serializeResult.Value, rsaFingerprint.Value);

        Assert.True(verifyResult.IsSuccess);
        Assert.True(verifyResult.Value);
    }

    private static TrustBundle CreateTestBundle() => new()
    {
        Metadata = new BundleMetadata
        {
            Name = "test-bundle",
            Description = "Test bundle for unit tests",
            Created = "2026-02-08T12:00:00Z"
        },
        Keys =
        [
            new TrustedKeyEntry
            {
                Fingerprint = "sha256:abc123",
                DisplayName = "Test Key"
            }
        ]
    };
}
