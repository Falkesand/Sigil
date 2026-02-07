using Sigil.Crypto;
using Sigil.Keys;
using Sigil.Signing;
using System.Text;

namespace Sigil.Core.Tests.Signing;

public class SigningRoundTripTests : IDisposable
{
    private readonly string _tempDir;
    private readonly KeyStore _store;
    private readonly string _artifactPath;

    public SigningRoundTripTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-test-" + Guid.NewGuid().ToString("N")[..8]);
        _store = new KeyStore(Path.Combine(_tempDir, "keys"));
        _artifactPath = Path.Combine(_tempDir, "test-artifact.txt");
        Directory.CreateDirectory(_tempDir);
        File.WriteAllText(_artifactPath, "This is a test artifact for signing verification.");
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    [Fact]
    public void Sign_ProducesValidEnvelope()
    {
        var fp = _store.GenerateKey();
        using var signer = _store.LoadSigner(fp);

        var envelope = ArtifactSigner.Sign(_artifactPath, signer, fp, "test-label");

        Assert.Equal("1.0", envelope.Version);
        Assert.Equal("test-artifact.txt", envelope.Subject.Name);
        Assert.True(envelope.Subject.Digests.ContainsKey("sha256"));
        Assert.True(envelope.Subject.Digests.ContainsKey("sha512"));
        Assert.Single(envelope.Signatures);
        Assert.Equal(fp.Value, envelope.Signatures[0].KeyId);
        Assert.Equal("ecdsa-p256", envelope.Signatures[0].Algorithm);
        Assert.Equal("test-label", envelope.Signatures[0].Label);
    }

    [Fact]
    public void SignAndVerify_RoundTrip_Succeeds()
    {
        var fp = _store.GenerateKey();
        using var signer = _store.LoadSigner(fp);

        var envelope = ArtifactSigner.Sign(_artifactPath, signer, fp);
        var result = SignatureValidator.Verify(_artifactPath, envelope, _store);

        Assert.True(result.ArtifactDigestMatch);
        Assert.True(result.AllSignaturesValid);
        Assert.Single(result.Signatures);
        Assert.True(result.Signatures[0].IsValid);
    }

    [Fact]
    public void Verify_TamperedArtifact_FailsDigestCheck()
    {
        var fp = _store.GenerateKey();
        using var signer = _store.LoadSigner(fp);

        var envelope = ArtifactSigner.Sign(_artifactPath, signer, fp);

        // Tamper with artifact
        File.WriteAllText(_artifactPath, "TAMPERED CONTENT");

        var result = SignatureValidator.Verify(_artifactPath, envelope, _store);
        Assert.False(result.ArtifactDigestMatch);
    }

    [Fact]
    public void Verify_WrongKey_FailsSignatureCheck()
    {
        var fp1 = _store.GenerateKey();
        var fp2 = _store.GenerateKey();

        using var signer1 = _store.LoadSigner(fp1);
        var envelope = ArtifactSigner.Sign(_artifactPath, signer1, fp1);

        // Replace keyId with a different key's fingerprint
        var tampered = new SignatureEnvelope
        {
            Subject = envelope.Subject,
            Signatures =
            [
                new SignatureEntry
                {
                    KeyId = fp2.Value, // wrong key
                    Algorithm = envelope.Signatures[0].Algorithm,
                    Value = envelope.Signatures[0].Value, // signature from key1
                    Timestamp = envelope.Signatures[0].Timestamp
                }
            ]
        };

        var result = SignatureValidator.Verify(_artifactPath, tampered, _store);
        Assert.True(result.ArtifactDigestMatch);
        Assert.False(result.AllSignaturesValid);
    }

    [Fact]
    public void Verify_UnknownKey_ReportsError()
    {
        var fp = _store.GenerateKey();
        using var signer = _store.LoadSigner(fp);
        var envelope = ArtifactSigner.Sign(_artifactPath, signer, fp);

        // Verify with a store that doesn't have the key
        var emptyStore = new KeyStore(Path.Combine(_tempDir, "empty-keys"));
        var result = SignatureValidator.Verify(_artifactPath, envelope, emptyStore);

        Assert.True(result.ArtifactDigestMatch);
        Assert.False(result.AllSignaturesValid);
        Assert.Contains("not found", result.Signatures[0].Error);
    }

    [Fact]
    public void MultipleSignatures_AllVerified()
    {
        var fp1 = _store.GenerateKey(label: "author");
        var fp2 = _store.GenerateKey(label: "auditor");

        using var signer1 = _store.LoadSigner(fp1);
        var artifactBytes = File.ReadAllBytes(_artifactPath);

        var envelope = ArtifactSigner.Sign(_artifactPath, signer1, fp1, "author");

        // Append second signature
        using var signer2 = _store.LoadSigner(fp2);
        ArtifactSigner.AppendSignature(envelope, artifactBytes, signer2, fp2, "auditor");

        Assert.Equal(2, envelope.Signatures.Count);

        var result = SignatureValidator.Verify(_artifactPath, envelope, _store);
        Assert.True(result.AllSignaturesValid);
        Assert.Equal(2, result.Signatures.Count);
    }

    [Fact]
    public void Serialize_Deserialize_RoundTrip()
    {
        var fp = _store.GenerateKey();
        using var signer = _store.LoadSigner(fp);
        var envelope = ArtifactSigner.Sign(_artifactPath, signer, fp, "serialize-test");

        var json = ArtifactSigner.Serialize(envelope);
        var deserialized = ArtifactSigner.Deserialize(json);

        Assert.Equal(envelope.Version, deserialized.Version);
        Assert.Equal(envelope.Subject.Name, deserialized.Subject.Name);
        Assert.Equal(envelope.Subject.Digests["sha256"], deserialized.Subject.Digests["sha256"]);
        Assert.Equal(envelope.Signatures[0].KeyId, deserialized.Signatures[0].KeyId);
        Assert.Equal(envelope.Signatures[0].Value, deserialized.Signatures[0].Value);

        // Deserialized envelope should still verify
        var result = SignatureValidator.Verify(_artifactPath, deserialized, _store);
        Assert.True(result.AllSignaturesValid);
    }
}
