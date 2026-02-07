using Sigil.Crypto;
using Sigil.Keys;
using Sigil.Signing;

namespace Sigil.Core.Tests.Signing;

public class SigningRoundTripTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _artifactPath;

    public SigningRoundTripTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-test-" + Guid.NewGuid().ToString("N")[..8]);
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
        using var signer = ECDsaP256Signer.Generate();
        var fp = KeyFingerprint.Compute(signer.PublicKey);

        var envelope = ArtifactSigner.Sign(_artifactPath, signer, fp, "test-label");

        Assert.Equal("1.0", envelope.Version);
        Assert.Equal("test-artifact.txt", envelope.Subject.Name);
        Assert.True(envelope.Subject.Digests.ContainsKey("sha256"));
        Assert.True(envelope.Subject.Digests.ContainsKey("sha512"));
        Assert.Single(envelope.Signatures);
        Assert.Equal(fp.Value, envelope.Signatures[0].KeyId);
        Assert.Equal("ecdsa-p256", envelope.Signatures[0].Algorithm);
        Assert.Equal("test-label", envelope.Signatures[0].Label);
        Assert.False(string.IsNullOrEmpty(envelope.Signatures[0].PublicKey));
    }

    [Fact]
    public void SignAndVerify_Ephemeral_RoundTrip_Succeeds()
    {
        using var signer = ECDsaP256Signer.Generate();
        var fp = KeyFingerprint.Compute(signer.PublicKey);

        var envelope = ArtifactSigner.Sign(_artifactPath, signer, fp);
        var result = SignatureValidator.Verify(_artifactPath, envelope);

        Assert.True(result.ArtifactDigestMatch);
        Assert.True(result.AllSignaturesValid);
        Assert.Single(result.Signatures);
        Assert.True(result.Signatures[0].IsValid);
    }

    [Fact]
    public void SignAndVerify_Persistent_RoundTrip_Succeeds()
    {
        // Generate and save key to PEM file
        using var signer = ECDsaP256Signer.Generate();
        var pemPath = Path.Combine(_tempDir, "testkey.pem");
        File.WriteAllText(pemPath, signer.ExportPrivateKeyPem());

        var fp = KeyFingerprint.Compute(signer.PublicKey);
        var envelope = ArtifactSigner.Sign(_artifactPath, signer, fp, "persistent");

        // Verify from envelope (no key store needed)
        var result = SignatureValidator.Verify(_artifactPath, envelope);

        Assert.True(result.ArtifactDigestMatch);
        Assert.True(result.AllSignaturesValid);

        // Also verify that loading from PEM produces the same fingerprint
        using var loadedSigner = ECDsaP256Signer.FromPem(File.ReadAllText(pemPath));
        var loadedFp = KeyFingerprint.Compute(loadedSigner.PublicKey);
        Assert.Equal(fp, loadedFp);
    }

    [Fact]
    public void Verify_TamperedArtifact_FailsDigestCheck()
    {
        using var signer = ECDsaP256Signer.Generate();
        var fp = KeyFingerprint.Compute(signer.PublicKey);

        var envelope = ArtifactSigner.Sign(_artifactPath, signer, fp);

        // Tamper with artifact
        File.WriteAllText(_artifactPath, "TAMPERED CONTENT");

        var result = SignatureValidator.Verify(_artifactPath, envelope);
        Assert.False(result.ArtifactDigestMatch);
    }

    [Fact]
    public void Verify_TamperedPublicKey_DetectsFingerPrintMismatch()
    {
        using var signer = ECDsaP256Signer.Generate();
        var fp = KeyFingerprint.Compute(signer.PublicKey);
        var envelope = ArtifactSigner.Sign(_artifactPath, signer, fp);

        // Replace publicKey in the envelope with a different key's public key
        using var otherSigner = ECDsaP256Signer.Generate();
        var tampered = new SignatureEnvelope
        {
            Subject = envelope.Subject,
            Signatures =
            [
                new SignatureEntry
                {
                    KeyId = envelope.Signatures[0].KeyId, // original fingerprint
                    Algorithm = envelope.Signatures[0].Algorithm,
                    PublicKey = Convert.ToBase64String(otherSigner.PublicKey), // different key
                    Value = envelope.Signatures[0].Value,
                    Timestamp = envelope.Signatures[0].Timestamp
                }
            ]
        };

        var result = SignatureValidator.Verify(_artifactPath, tampered);
        Assert.True(result.ArtifactDigestMatch);
        Assert.False(result.AllSignaturesValid);
        Assert.Contains("fingerprint does not match", result.Signatures[0].Error);
    }

    [Fact]
    public void Verify_WrongKey_FailsSignatureCheck()
    {
        using var signer1 = ECDsaP256Signer.Generate();
        using var signer2 = ECDsaP256Signer.Generate();
        var fp2 = KeyFingerprint.Compute(signer2.PublicKey);

        var fp1 = KeyFingerprint.Compute(signer1.PublicKey);
        var envelope = ArtifactSigner.Sign(_artifactPath, signer1, fp1);

        // Replace with signer2's key AND matching fingerprint — signature won't verify
        var tampered = new SignatureEnvelope
        {
            Subject = envelope.Subject,
            Signatures =
            [
                new SignatureEntry
                {
                    KeyId = fp2.Value, // signer2's fingerprint
                    Algorithm = envelope.Signatures[0].Algorithm,
                    PublicKey = Convert.ToBase64String(signer2.PublicKey), // signer2's key
                    Value = envelope.Signatures[0].Value, // signature from signer1
                    Timestamp = envelope.Signatures[0].Timestamp
                }
            ]
        };

        var result = SignatureValidator.Verify(_artifactPath, tampered);
        Assert.True(result.ArtifactDigestMatch);
        Assert.False(result.AllSignaturesValid);
    }

    [Fact]
    public void Verify_MissingPublicKey_ReportsError()
    {
        using var signer = ECDsaP256Signer.Generate();
        var fp = KeyFingerprint.Compute(signer.PublicKey);
        var envelope = ArtifactSigner.Sign(_artifactPath, signer, fp);

        // Create envelope with empty publicKey
        var noKey = new SignatureEnvelope
        {
            Subject = envelope.Subject,
            Signatures =
            [
                new SignatureEntry
                {
                    KeyId = fp.Value,
                    Algorithm = envelope.Signatures[0].Algorithm,
                    PublicKey = "",
                    Value = envelope.Signatures[0].Value,
                    Timestamp = envelope.Signatures[0].Timestamp
                }
            ]
        };

        var result = SignatureValidator.Verify(_artifactPath, noKey);
        Assert.True(result.ArtifactDigestMatch);
        Assert.False(result.AllSignaturesValid);
        Assert.Contains("not found in signature entry", result.Signatures[0].Error);
    }

    [Fact]
    public void MultipleSignatures_AllVerified()
    {
        using var signer1 = ECDsaP256Signer.Generate();
        using var signer2 = ECDsaP256Signer.Generate();
        var fp1 = KeyFingerprint.Compute(signer1.PublicKey);
        var fp2 = KeyFingerprint.Compute(signer2.PublicKey);

        var artifactBytes = File.ReadAllBytes(_artifactPath);
        var envelope = ArtifactSigner.Sign(_artifactPath, signer1, fp1, "author");

        // Append second signature
        ArtifactSigner.AppendSignature(envelope, artifactBytes, signer2, fp2, "auditor");

        Assert.Equal(2, envelope.Signatures.Count);

        var result = SignatureValidator.Verify(_artifactPath, envelope);
        Assert.True(result.AllSignaturesValid);
        Assert.Equal(2, result.Signatures.Count);
    }

    [Fact]
    public void Serialize_Deserialize_RoundTrip()
    {
        using var signer = ECDsaP256Signer.Generate();
        var fp = KeyFingerprint.Compute(signer.PublicKey);
        var envelope = ArtifactSigner.Sign(_artifactPath, signer, fp, "serialize-test");

        var json = ArtifactSigner.Serialize(envelope);
        var deserialized = ArtifactSigner.Deserialize(json);

        Assert.Equal(envelope.Version, deserialized.Version);
        Assert.Equal(envelope.Subject.Name, deserialized.Subject.Name);
        Assert.Equal(envelope.Subject.Digests["sha256"], deserialized.Subject.Digests["sha256"]);
        Assert.Equal(envelope.Signatures[0].KeyId, deserialized.Signatures[0].KeyId);
        Assert.Equal(envelope.Signatures[0].PublicKey, deserialized.Signatures[0].PublicKey);
        Assert.Equal(envelope.Signatures[0].Value, deserialized.Signatures[0].Value);

        // Deserialized envelope should still verify
        var result = SignatureValidator.Verify(_artifactPath, deserialized);
        Assert.True(result.AllSignaturesValid);
    }

    [Fact]
    public void EmbeddedPublicKey_MatchesSignerPublicKey()
    {
        using var signer = ECDsaP256Signer.Generate();
        var fp = KeyFingerprint.Compute(signer.PublicKey);
        var envelope = ArtifactSigner.Sign(_artifactPath, signer, fp);

        var embeddedKey = Convert.FromBase64String(envelope.Signatures[0].PublicKey);
        Assert.Equal(signer.PublicKey, embeddedKey);
    }

    [Fact]
    public void Verify_TamperedTimestamp_FailsSignatureCheck()
    {
        using var signer = ECDsaP256Signer.Generate();
        var fp = KeyFingerprint.Compute(signer.PublicKey);
        var envelope = ArtifactSigner.Sign(_artifactPath, signer, fp);

        var original = envelope.Signatures[0];
        var tampered = new SignatureEnvelope
        {
            Subject = envelope.Subject,
            Signatures =
            [
                new SignatureEntry
                {
                    KeyId = original.KeyId,
                    Algorithm = original.Algorithm,
                    PublicKey = original.PublicKey,
                    Value = original.Value,
                    Timestamp = "2020-01-01T00:00:00Z", // backdated
                    Label = original.Label
                }
            ]
        };

        var result = SignatureValidator.Verify(_artifactPath, tampered);
        Assert.True(result.ArtifactDigestMatch);
        Assert.False(result.AllSignaturesValid);
    }

    [Fact]
    public void Verify_TamperedLabel_FailsSignatureCheck()
    {
        using var signer = ECDsaP256Signer.Generate();
        var fp = KeyFingerprint.Compute(signer.PublicKey);
        var envelope = ArtifactSigner.Sign(_artifactPath, signer, fp, "ci-test");

        var original = envelope.Signatures[0];
        var tampered = new SignatureEnvelope
        {
            Subject = envelope.Subject,
            Signatures =
            [
                new SignatureEntry
                {
                    KeyId = original.KeyId,
                    Algorithm = original.Algorithm,
                    PublicKey = original.PublicKey,
                    Value = original.Value,
                    Timestamp = original.Timestamp,
                    Label = "security-audit" // relabeled
                }
            ]
        };

        var result = SignatureValidator.Verify(_artifactPath, tampered);
        Assert.True(result.ArtifactDigestMatch);
        Assert.False(result.AllSignaturesValid);
    }
}
