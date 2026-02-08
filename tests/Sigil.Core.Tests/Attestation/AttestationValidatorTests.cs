using System.Text.Json;
using Sigil.Attestation;
using Sigil.Crypto;
using Sigil.Keys;

namespace Sigil.Core.Tests.Attestation;

public class AttestationValidatorTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _artifactPath;
    private readonly byte[] _artifactBytes;

    public AttestationValidatorTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-attval-test-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
        _artifactPath = Path.Combine(_tempDir, "test-artifact.bin");
        _artifactBytes = "attestation validator test content"u8.ToArray();
        File.WriteAllBytes(_artifactPath, _artifactBytes);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    private (DsseEnvelope envelope, ISigner signer) CreateSignedEnvelope()
    {
        var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var fingerprint = KeyFingerprint.Compute(signer.PublicKey);

        var statement = AttestationCreator.CreateStatement(
            "test-artifact.bin", _artifactBytes,
            "https://slsa.dev/provenance/v1");

        var envelope = AttestationCreator.Sign(statement, signer, fingerprint);
        return (envelope, signer);
    }

    [Fact]
    public void Verify_valid_attestation_succeeds()
    {
        var (envelope, signer) = CreateSignedEnvelope();
        using (signer)
        {
            var result = AttestationValidator.Verify(_artifactBytes, envelope);

            Assert.True(result.SubjectDigestMatch);
            Assert.Single(result.Signatures);
            Assert.True(result.Signatures[0].IsValid);
            Assert.True(result.AllSignaturesValid);
        }
    }

    [Fact]
    public void Verify_from_file_path_succeeds()
    {
        var (envelope, signer) = CreateSignedEnvelope();
        using (signer)
        {
            var result = AttestationValidator.Verify(_artifactPath, envelope);

            Assert.True(result.SubjectDigestMatch);
            Assert.True(result.AllSignaturesValid);
        }
    }

    [Fact]
    public void Verify_wrong_artifact_digest_mismatch()
    {
        var (envelope, signer) = CreateSignedEnvelope();
        using (signer)
        {
            var wrongBytes = "different content entirely"u8.ToArray();

            var result = AttestationValidator.Verify(wrongBytes, envelope);

            Assert.False(result.SubjectDigestMatch);
            Assert.False(result.AllSignaturesValid);
        }
    }

    [Fact]
    public void Verify_tampered_payload_signature_fails()
    {
        var (envelope, signer) = CreateSignedEnvelope();
        using (signer)
        {
            // Tamper with the payload
            var tamperedStatement = AttestationCreator.CreateStatement(
                "test-artifact.bin", _artifactBytes,
                "https://example.com/tampered");
            var tamperedJson = JsonSerializer.SerializeToUtf8Bytes(tamperedStatement);
            var tamperedEnvelope = new DsseEnvelope
            {
                Payload = Convert.ToBase64String(tamperedJson),
                Signatures = [envelope.Signatures[0]]
            };

            var result = AttestationValidator.Verify(_artifactBytes, tamperedEnvelope);

            // Digest still matches the artifact, but signature is over different payload
            Assert.True(result.SubjectDigestMatch);
            Assert.False(result.Signatures[0].IsValid);
        }
    }

    [Fact]
    public void Verify_tampered_signature_value_fails()
    {
        var (envelope, signer) = CreateSignedEnvelope();
        using (signer)
        {
            var original = envelope.Signatures[0];
            var tampered = new DsseSignature
            {
                KeyId = original.KeyId,
                Sig = Convert.ToBase64String(new byte[64]),
                Algorithm = original.Algorithm,
                PublicKey = original.PublicKey,
                Timestamp = original.Timestamp
            };
            envelope.Signatures[0] = tampered;

            var result = AttestationValidator.Verify(_artifactBytes, envelope);

            Assert.False(result.Signatures[0].IsValid);
        }
    }

    [Fact]
    public void Verify_wrong_keyid_fails()
    {
        var (envelope, signer) = CreateSignedEnvelope();
        using (signer)
        {
            var original = envelope.Signatures[0];
            var tampered = new DsseSignature
            {
                KeyId = "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                Sig = original.Sig,
                Algorithm = original.Algorithm,
                PublicKey = original.PublicKey,
                Timestamp = original.Timestamp
            };
            envelope.Signatures[0] = tampered;

            var result = AttestationValidator.Verify(_artifactBytes, envelope);

            Assert.False(result.Signatures[0].IsValid);
            Assert.Contains("fingerprint", result.Signatures[0].Error);
        }
    }

    [Fact]
    public void Verify_missing_public_key_fails()
    {
        var (envelope, signer) = CreateSignedEnvelope();
        using (signer)
        {
            var original = envelope.Signatures[0];
            var tampered = new DsseSignature
            {
                KeyId = original.KeyId,
                Sig = original.Sig,
                Algorithm = original.Algorithm,
                PublicKey = "",
                Timestamp = original.Timestamp
            };
            envelope.Signatures[0] = tampered;

            var result = AttestationValidator.Verify(_artifactBytes, envelope);

            Assert.False(result.Signatures[0].IsValid);
            Assert.Contains("Public key not found", result.Signatures[0].Error);
        }
    }

    [Fact]
    public void Verify_multiple_signatures_both_valid()
    {
        using var signer1 = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        using var signer2 = SignerFactory.Generate(SigningAlgorithm.ECDsaP384);
        var fp1 = KeyFingerprint.Compute(signer1.PublicKey);
        var fp2 = KeyFingerprint.Compute(signer2.PublicKey);

        var statement = AttestationCreator.CreateStatement(
            "test-artifact.bin", _artifactBytes,
            "https://slsa.dev/provenance/v1");

        var envelope = AttestationCreator.Sign(statement, signer1, fp1);
        AttestationCreator.AppendSignature(envelope, signer2, fp2);

        var result = AttestationValidator.Verify(_artifactBytes, envelope);

        Assert.True(result.SubjectDigestMatch);
        Assert.Equal(2, result.Signatures.Count);
        Assert.True(result.AllSignaturesValid);
    }

    [Fact]
    public void Verify_multiple_signatures_one_tampered()
    {
        using var signer1 = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        using var signer2 = SignerFactory.Generate(SigningAlgorithm.ECDsaP384);
        var fp1 = KeyFingerprint.Compute(signer1.PublicKey);
        var fp2 = KeyFingerprint.Compute(signer2.PublicKey);

        var statement = AttestationCreator.CreateStatement(
            "test-artifact.bin", _artifactBytes,
            "https://slsa.dev/provenance/v1");

        var envelope = AttestationCreator.Sign(statement, signer1, fp1);
        AttestationCreator.AppendSignature(envelope, signer2, fp2);

        // Tamper second signature
        var original = envelope.Signatures[1];
        envelope.Signatures[1] = new DsseSignature
        {
            KeyId = original.KeyId,
            Sig = Convert.ToBase64String(new byte[96]),
            Algorithm = original.Algorithm,
            PublicKey = original.PublicKey,
            Timestamp = original.Timestamp
        };

        var result = AttestationValidator.Verify(_artifactBytes, envelope);

        Assert.True(result.AnySignatureValid);
        Assert.False(result.AllSignaturesValid);
    }

    [Fact]
    public void Verify_extracts_statement()
    {
        var (envelope, signer) = CreateSignedEnvelope();
        using (signer)
        {
            var result = AttestationValidator.Verify(_artifactBytes, envelope);

            Assert.NotNull(result.Statement);
            Assert.Equal("https://in-toto.io/Statement/v1", result.Statement.Type);
            Assert.Equal("https://slsa.dev/provenance/v1", result.Statement.PredicateType);
        }
    }

    [Fact]
    public void Verify_invalid_payload_returns_digest_mismatch()
    {
        var envelope = new DsseEnvelope
        {
            Payload = Convert.ToBase64String("not json"u8),
            Signatures =
            [
                new DsseSignature
                {
                    KeyId = "sha256:abc",
                    Sig = "sig",
                    Algorithm = "ecdsa-p256",
                    PublicKey = "pk",
                    Timestamp = "2026-01-01T00:00:00Z"
                }
            ]
        };

        var result = AttestationValidator.Verify(_artifactBytes, envelope);

        Assert.False(result.SubjectDigestMatch);
        Assert.Null(result.Statement);
    }

    [Fact]
    public void Verify_missing_file_throws()
    {
        var envelope = new DsseEnvelope { Payload = Convert.ToBase64String("x"u8) };

        Assert.Throws<FileNotFoundException>(() =>
            AttestationValidator.Verify(
                Path.Combine(_tempDir, "nonexistent.bin"), envelope));
    }

    [Fact]
    public void Verify_with_predicate_content_preserved()
    {
        using var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var fingerprint = KeyFingerprint.Compute(signer.PublicKey);

        var predicate = JsonSerializer.SerializeToElement(new
        {
            builder = new { id = "github-actions" },
            buildType = "https://slsa.dev/build/v1"
        });

        var statement = AttestationCreator.CreateStatement(
            "test-artifact.bin", _artifactBytes,
            "https://slsa.dev/provenance/v1",
            predicate);

        var envelope = AttestationCreator.Sign(statement, signer, fingerprint);

        var result = AttestationValidator.Verify(_artifactBytes, envelope);

        Assert.True(result.AllSignaturesValid);
        Assert.NotNull(result.Statement);
        Assert.NotNull(result.Statement.Predicate);
        Assert.Equal("github-actions",
            result.Statement.Predicate.Value.GetProperty("builder").GetProperty("id").GetString());
    }

    [Fact]
    public void Verify_algorithm_is_populated()
    {
        var (envelope, signer) = CreateSignedEnvelope();
        using (signer)
        {
            var result = AttestationValidator.Verify(_artifactBytes, envelope);

            Assert.Equal("ecdsa-p256", result.Signatures[0].Algorithm);
        }
    }

    [Fact]
    public void Verify_empty_signatures_list()
    {
        using var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var fingerprint = KeyFingerprint.Compute(signer.PublicKey);

        var statement = AttestationCreator.CreateStatement(
            "test-artifact.bin", _artifactBytes,
            "https://slsa.dev/provenance/v1");

        var envelope = AttestationCreator.Sign(statement, signer, fingerprint);
        envelope.Signatures.Clear();

        var result = AttestationValidator.Verify(_artifactBytes, envelope);

        Assert.True(result.SubjectDigestMatch);
        Assert.Empty(result.Signatures);
        Assert.False(result.AnySignatureValid);
    }
}
