using System.Text.Json;
using Sigil.Attestation;
using Sigil.Crypto;
using Sigil.Keys;

namespace Sigil.Core.Tests.Attestation;

public class AttestationCreatorTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _artifactPath;
    private readonly byte[] _artifactBytes;

    public AttestationCreatorTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-att-test-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
        _artifactPath = Path.Combine(_tempDir, "test-artifact.bin");
        _artifactBytes = "test artifact content for attestation"u8.ToArray();
        File.WriteAllBytes(_artifactPath, _artifactBytes);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    [Fact]
    public void CreateStatement_from_path_sets_subject()
    {
        var statement = AttestationCreator.CreateStatement(
            _artifactPath,
            "https://slsa.dev/provenance/v1");

        Assert.Single(statement.Subject);
        Assert.Equal("test-artifact.bin", statement.Subject[0].Name);
        Assert.True(statement.Subject[0].Digest.ContainsKey("sha256"));
        Assert.Equal("https://in-toto.io/Statement/v1", statement.Type);
    }

    [Fact]
    public void CreateStatement_from_bytes_sets_digest()
    {
        var expectedDigest = HashAlgorithms.Sha256Hex(_artifactBytes);

        var statement = AttestationCreator.CreateStatement(
            "artifact.tar.gz", _artifactBytes,
            "https://slsa.dev/provenance/v1");

        Assert.Equal(expectedDigest, statement.Subject[0].Digest["sha256"]);
    }

    [Fact]
    public void CreateStatement_with_predicate()
    {
        var predicate = JsonSerializer.SerializeToElement(new { builder = "github-actions", buildType = "ci" });

        var statement = AttestationCreator.CreateStatement(
            "artifact.tar.gz", _artifactBytes,
            "https://slsa.dev/provenance/v1",
            predicate);

        Assert.NotNull(statement.Predicate);
        Assert.Equal("github-actions", statement.Predicate.Value.GetProperty("builder").GetString());
    }

    [Fact]
    public void CreateStatement_missing_file_throws()
    {
        Assert.Throws<FileNotFoundException>(() =>
            AttestationCreator.CreateStatement(
                Path.Combine(_tempDir, "nonexistent.bin"),
                "https://slsa.dev/provenance/v1"));
    }

    [Fact]
    public void Sign_produces_valid_envelope()
    {
        using var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var fingerprint = KeyFingerprint.Compute(signer.PublicKey);

        var statement = AttestationCreator.CreateStatement(
            "artifact.bin", _artifactBytes,
            "https://slsa.dev/provenance/v1");

        var envelope = AttestationCreator.Sign(statement, signer, fingerprint);

        Assert.Equal("application/vnd.in-toto+json", envelope.PayloadType);
        Assert.Single(envelope.Signatures);
        Assert.Equal(fingerprint.Value, envelope.Signatures[0].KeyId);
        Assert.Equal("ecdsa-p256", envelope.Signatures[0].Algorithm);
        Assert.NotEmpty(envelope.Signatures[0].Sig);
        Assert.NotEmpty(envelope.Signatures[0].PublicKey);
        Assert.NotEmpty(envelope.Signatures[0].Timestamp);
    }

    [Fact]
    public async Task SignAsync_produces_valid_envelope()
    {
        using var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var fingerprint = KeyFingerprint.Compute(signer.PublicKey);

        var statement = AttestationCreator.CreateStatement(
            "artifact.bin", _artifactBytes,
            "https://slsa.dev/provenance/v1");

        var envelope = await AttestationCreator.SignAsync(statement, signer, fingerprint);

        Assert.Single(envelope.Signatures);
        Assert.Equal(fingerprint.Value, envelope.Signatures[0].KeyId);
    }

    [Fact]
    public void AppendSignature_adds_second_signature()
    {
        using var signer1 = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        using var signer2 = SignerFactory.Generate(SigningAlgorithm.ECDsaP384);
        var fp1 = KeyFingerprint.Compute(signer1.PublicKey);
        var fp2 = KeyFingerprint.Compute(signer2.PublicKey);

        var statement = AttestationCreator.CreateStatement(
            "artifact.bin", _artifactBytes,
            "https://slsa.dev/provenance/v1");

        var envelope = AttestationCreator.Sign(statement, signer1, fp1);
        AttestationCreator.AppendSignature(envelope, signer2, fp2);

        Assert.Equal(2, envelope.Signatures.Count);
        Assert.Equal(fp1.Value, envelope.Signatures[0].KeyId);
        Assert.Equal(fp2.Value, envelope.Signatures[1].KeyId);
        Assert.Equal("ecdsa-p384", envelope.Signatures[1].Algorithm);
    }

    [Fact]
    public void Serialize_Deserialize_roundtrip()
    {
        using var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var fingerprint = KeyFingerprint.Compute(signer.PublicKey);

        var statement = AttestationCreator.CreateStatement(
            "artifact.bin", _artifactBytes,
            "https://slsa.dev/provenance/v1");

        var envelope = AttestationCreator.Sign(statement, signer, fingerprint);
        var json = AttestationCreator.Serialize(envelope);
        var result = AttestationCreator.Deserialize(json);

        Assert.True(result.IsSuccess);
        Assert.Equal(envelope.PayloadType, result.Value.PayloadType);
        Assert.Equal(envelope.Payload, result.Value.Payload);
        Assert.Single(result.Value.Signatures);
    }

    [Fact]
    public void Deserialize_invalid_json_returns_failure()
    {
        var result = AttestationCreator.Deserialize("not json {{{");

        Assert.False(result.IsSuccess);
        Assert.Equal(AttestationErrorKind.DeserializationFailed, result.ErrorKind);
    }

    [Fact]
    public void ExtractStatement_roundtrip()
    {
        using var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var fingerprint = KeyFingerprint.Compute(signer.PublicKey);

        var predicate = JsonSerializer.SerializeToElement(new { step = "build" });
        var statement = AttestationCreator.CreateStatement(
            "artifact.bin", _artifactBytes,
            "https://slsa.dev/provenance/v1",
            predicate);

        var envelope = AttestationCreator.Sign(statement, signer, fingerprint);
        var extracted = AttestationCreator.ExtractStatement(envelope);

        Assert.True(extracted.IsSuccess);
        Assert.Equal(statement.Type, extracted.Value.Type);
        Assert.Equal(statement.PredicateType, extracted.Value.PredicateType);
        Assert.Equal("artifact.bin", extracted.Value.Subject[0].Name);
    }

    [Fact]
    public void ExtractStatement_invalid_payload_returns_failure()
    {
        var envelope = new DsseEnvelope
        {
            Payload = Convert.ToBase64String("not json"u8)
        };

        var result = AttestationCreator.ExtractStatement(envelope);

        Assert.False(result.IsSuccess);
        Assert.Equal(AttestationErrorKind.DeserializationFailed, result.ErrorKind);
    }

    [Fact]
    public void Sign_embeds_public_key_for_self_contained_verification()
    {
        using var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var fingerprint = KeyFingerprint.Compute(signer.PublicKey);

        var statement = AttestationCreator.CreateStatement(
            "artifact.bin", _artifactBytes,
            "https://slsa.dev/provenance/v1");

        var envelope = AttestationCreator.Sign(statement, signer, fingerprint);

        var embeddedPk = Convert.FromBase64String(envelope.Signatures[0].PublicKey);
        Assert.Equal(signer.PublicKey, embeddedPk);
    }

    [Fact]
    public void Sign_payload_is_base64_encoded_statement()
    {
        using var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var fingerprint = KeyFingerprint.Compute(signer.PublicKey);

        var statement = AttestationCreator.CreateStatement(
            "artifact.bin", _artifactBytes,
            "https://slsa.dev/provenance/v1");

        var envelope = AttestationCreator.Sign(statement, signer, fingerprint);

        var payloadBytes = Convert.FromBase64String(envelope.Payload);
        var decoded = JsonSerializer.Deserialize<InTotoStatement>(payloadBytes);

        Assert.NotNull(decoded);
        Assert.Equal("https://in-toto.io/Statement/v1", decoded.Type);
    }
}
