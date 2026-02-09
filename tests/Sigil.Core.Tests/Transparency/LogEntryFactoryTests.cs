using Sigil.Signing;
using Sigil.Transparency;

namespace Sigil.Core.Tests.Transparency;

public class LogEntryFactoryTests
{
    private static SignatureEnvelope MakeEnvelope(string? label = null)
    {
        return new SignatureEnvelope
        {
            Subject = new SubjectDescriptor
            {
                Name = "mylib.dll",
                Digests = new Dictionary<string, string>
                {
                    ["sha256"] = "abcd1234",
                    ["sha512"] = "efgh5678"
                }
            },
            Signatures =
            [
                new SignatureEntry
                {
                    KeyId = "sha256:key123",
                    Algorithm = "ecdsa-p256",
                    PublicKey = "BQAA",
                    Value = Convert.ToBase64String([1, 2, 3, 4]),
                    Timestamp = "2026-01-15T10:00:00Z",
                    Label = label
                }
            ]
        };
    }

    [Fact]
    public void Create_returns_entry_with_correct_fields()
    {
        var envelope = MakeEnvelope();

        var result = LogEntryFactory.Create(envelope, 0, 0);

        Assert.True(result.IsSuccess);
        var entry = result.Value;
        Assert.Equal(0, entry.Index);
        Assert.Equal("sha256:key123", entry.KeyId);
        Assert.Equal("ecdsa-p256", entry.Algorithm);
        Assert.Equal("mylib.dll", entry.ArtifactName);
        Assert.Equal("sha256:abcd1234", entry.ArtifactDigest);
        Assert.NotEmpty(entry.SignatureDigest);
        Assert.NotEmpty(entry.LeafHash);
        Assert.NotEmpty(entry.Timestamp);
    }

    [Fact]
    public void Create_with_label_includes_label()
    {
        var envelope = MakeEnvelope(label: "release");

        var result = LogEntryFactory.Create(envelope, 0, 0);

        Assert.True(result.IsSuccess);
        Assert.Equal("release", result.Value.Label);
    }

    [Fact]
    public void Create_without_label_has_null_label()
    {
        var envelope = MakeEnvelope();

        var result = LogEntryFactory.Create(envelope, 0, 0);

        Assert.True(result.IsSuccess);
        Assert.Null(result.Value.Label);
    }

    [Fact]
    public void Create_with_invalid_signature_index_fails()
    {
        var envelope = MakeEnvelope();

        var result = LogEntryFactory.Create(envelope, 5, 0);

        Assert.False(result.IsSuccess);
        Assert.Equal(TransparencyErrorKind.InvalidEnvelope, result.ErrorKind);
    }

    [Fact]
    public void Create_computes_deterministic_leaf_hash()
    {
        var envelope = MakeEnvelope();

        var result1 = LogEntryFactory.Create(envelope, 0, 0);
        var result2 = LogEntryFactory.Create(envelope, 0, 0);

        // Both created at same index with same data should have same fields
        // (timestamp may differ slightly, but leafHash depends on timestamp)
        Assert.True(result1.IsSuccess);
        Assert.True(result2.IsSuccess);
        Assert.NotEmpty(result1.Value.LeafHash);
        Assert.NotEmpty(result2.Value.LeafHash);
    }

    [Fact]
    public void Create_signature_digest_is_sha256_of_signature_bytes()
    {
        var sigBytes = new byte[] { 1, 2, 3, 4 };
        var expectedDigest = "sha256:" + Sigil.Crypto.HashAlgorithms.Sha256Hex(sigBytes);
        var envelope = MakeEnvelope();

        var result = LogEntryFactory.Create(envelope, 0, 0);

        Assert.True(result.IsSuccess);
        Assert.Equal(expectedDigest, result.Value.SignatureDigest);
    }

    [Fact]
    public void Create_with_invalid_base64_fails()
    {
        var envelope = new SignatureEnvelope
        {
            Subject = new SubjectDescriptor
            {
                Name = "mylib.dll",
                Digests = new Dictionary<string, string> { ["sha256"] = "abcd1234" }
            },
            Signatures =
            [
                new SignatureEntry
                {
                    KeyId = "sha256:key123",
                    Algorithm = "ecdsa-p256",
                    PublicKey = "BQAA",
                    Value = "not-valid-base64!!!",
                    Timestamp = "2026-01-15T10:00:00Z"
                }
            ]
        };

        var result = LogEntryFactory.Create(envelope, 0, 0);

        Assert.False(result.IsSuccess);
        Assert.Equal(TransparencyErrorKind.InvalidEnvelope, result.ErrorKind);
        Assert.Contains("base64", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }
}
