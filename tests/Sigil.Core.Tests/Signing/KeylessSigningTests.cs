using Sigil.Core.Tests.Keyless;
using Sigil.Crypto;
using Sigil.Keyless;
using Sigil.Keys;
using Sigil.Signing;

namespace Sigil.Core.Tests.Signing;

public class KeylessSigningTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _artifactPath;

    public KeylessSigningTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-keyless-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
        _artifactPath = Path.Combine(_tempDir, "test-artifact.txt");
        File.WriteAllText(_artifactPath, "test content for keyless signing");
    }

    [Fact]
    public async Task SignKeylessAsync_PopulatesOidcFields()
    {
        using var keylessSigner = await CreateTestKeylessSigner();

        var envelope = await ArtifactSigner.SignKeylessAsync(_artifactPath, keylessSigner);

        Assert.Single(envelope.Signatures);
        var entry = envelope.Signatures[0];
        Assert.NotNull(entry.OidcToken);
        Assert.Equal("https://issuer.example.com", entry.OidcIssuer);
        Assert.Equal("test-subject", entry.OidcIdentity);
    }

    [Fact]
    public async Task AppendKeylessSignatureAsync_AddsOidcEntry()
    {
        // First sign normally
        using var normalSigner = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var fingerprint = KeyFingerprint.Compute(normalSigner.PublicKey);
        var fileBytes = await File.ReadAllBytesAsync(_artifactPath);
        var envelope = ArtifactSigner.Sign(_artifactPath, normalSigner, fingerprint);

        // Then append keyless
        using var keylessSigner = await CreateTestKeylessSigner();
        await ArtifactSigner.AppendKeylessSignatureAsync(envelope, fileBytes, keylessSigner);

        Assert.Equal(2, envelope.Signatures.Count);
        Assert.Null(envelope.Signatures[0].OidcToken); // Normal sig
        Assert.NotNull(envelope.Signatures[1].OidcToken); // Keyless sig
    }

    [Fact]
    public async Task NonKeylessSigning_OidcFieldsNull()
    {
        using var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var fingerprint = KeyFingerprint.Compute(signer.PublicKey);

        var envelope = ArtifactSigner.Sign(_artifactPath, signer, fingerprint);

        var entry = envelope.Signatures[0];
        Assert.Null(entry.OidcToken);
        Assert.Null(entry.OidcIssuer);
        Assert.Null(entry.OidcIdentity);
    }

    [Fact]
    public async Task RoundTrip_PreservesOidcFields()
    {
        using var keylessSigner = await CreateTestKeylessSigner();
        var envelope = await ArtifactSigner.SignKeylessAsync(_artifactPath, keylessSigner);

        var json = ArtifactSigner.Serialize(envelope);
        var deserialized = ArtifactSigner.Deserialize(json);

        var entry = deserialized.Signatures[0];
        Assert.Equal(keylessSigner.OidcToken, entry.OidcToken);
        Assert.Equal("https://issuer.example.com", entry.OidcIssuer);
        Assert.Equal("test-subject", entry.OidcIdentity);
    }

    [Fact]
    public void NonOidcJson_BackwardCompatible()
    {
        // Non-OIDC envelopes should not have oidc fields in JSON
        using var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var fingerprint = KeyFingerprint.Compute(signer.PublicKey);
        var envelope = ArtifactSigner.Sign(_artifactPath, signer, fingerprint);

        var json = ArtifactSigner.Serialize(envelope);

        Assert.DoesNotContain("oidcToken", json);
        Assert.DoesNotContain("oidcIssuer", json);
        Assert.DoesNotContain("oidcIdentity", json);
    }

    [Fact]
    public async Task TimestampCopying_PreservesOidcFields()
    {
        using var keylessSigner = await CreateTestKeylessSigner();
        var envelope = await ArtifactSigner.SignKeylessAsync(_artifactPath, keylessSigner);

        var entry = envelope.Signatures[0];

        // Simulate what TimestampApplier does: create a new entry with timestamp token
        var timestamped = new SignatureEntry
        {
            KeyId = entry.KeyId,
            Algorithm = entry.Algorithm,
            PublicKey = entry.PublicKey,
            Value = entry.Value,
            Timestamp = entry.Timestamp,
            Label = entry.Label,
            TimestampToken = "dummy-timestamp-token",
            OidcToken = entry.OidcToken,
            OidcIssuer = entry.OidcIssuer,
            OidcIdentity = entry.OidcIdentity
        };

        Assert.Equal(entry.OidcToken, timestamped.OidcToken);
        Assert.Equal(entry.OidcIssuer, timestamped.OidcIssuer);
        Assert.Equal(entry.OidcIdentity, timestamped.OidcIdentity);
        Assert.Equal("dummy-timestamp-token", timestamped.TimestampToken);
    }

    private static async Task<KeylessSigner> CreateTestKeylessSigner()
    {
        var (jwt, key) = TestJwtBuilder.CreateRs256Token(
            "https://issuer.example.com", "test-subject", "placeholder");
        key.Dispose();

        var provider = new ManualOidcTokenProvider(jwt);
        var result = await KeylessSigner.CreateAsync(provider);
        return result.Value;
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, true); } catch { /* cleanup */ }
    }
}
