using Sigil.Signing;
using Sigil.Transparency;

namespace Sigil.Core.Tests.Transparency;

public class TransparencyLogAppendTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _logPath;

    public TransparencyLogAppendTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
        _logPath = Path.Combine(_tempDir, ".sigil.log.jsonl");
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    private static SignatureEnvelope MakeEnvelope(byte[]? sigBytes = null, string? label = null, string name = "test.dll")
    {
        sigBytes ??= [1, 2, 3, 4];
        return new SignatureEnvelope
        {
            Subject = new SubjectDescriptor
            {
                Name = name,
                Digests = new Dictionary<string, string> { ["sha256"] = "aabb" }
            },
            Signatures =
            [
                new SignatureEntry
                {
                    KeyId = "sha256:key1",
                    Algorithm = "ecdsa-p256",
                    PublicKey = "BQAA",
                    Value = Convert.ToBase64String(sigBytes),
                    Timestamp = "2026-01-15T10:00:00Z",
                    Label = label
                }
            ]
        };
    }

    [Fact]
    public void Append_first_entry_creates_log_file()
    {
        var log = new TransparencyLog(_logPath);

        var result = log.Append(MakeEnvelope());

        Assert.True(result.IsSuccess);
        Assert.Equal(0, result.Value.Index);
        Assert.True(File.Exists(_logPath));
    }

    [Fact]
    public void Append_creates_checkpoint_file()
    {
        var log = new TransparencyLog(_logPath);

        log.Append(MakeEnvelope());

        var checkpointPath = Path.Combine(_tempDir, ".sigil.checkpoint");
        Assert.True(File.Exists(checkpointPath));
    }

    [Fact]
    public void Append_multiple_entries_increments_index()
    {
        var log = new TransparencyLog(_logPath);

        var r1 = log.Append(MakeEnvelope([1, 2, 3]));
        var r2 = log.Append(MakeEnvelope([4, 5, 6]));
        var r3 = log.Append(MakeEnvelope([7, 8, 9]));

        Assert.Equal(0, r1.Value.Index);
        Assert.Equal(1, r2.Value.Index);
        Assert.Equal(2, r3.Value.Index);
    }

    [Fact]
    public void Append_duplicate_signature_fails()
    {
        var log = new TransparencyLog(_logPath);
        var envelope = MakeEnvelope();

        log.Append(envelope);
        var result = log.Append(envelope);

        Assert.False(result.IsSuccess);
        Assert.Equal(TransparencyErrorKind.DuplicateEntry, result.ErrorKind);
    }

    [Fact]
    public void Append_invalid_signature_index_fails()
    {
        var log = new TransparencyLog(_logPath);

        var result = log.Append(MakeEnvelope(), signatureIndex: 5);

        Assert.False(result.IsSuccess);
        Assert.Equal(TransparencyErrorKind.InvalidEnvelope, result.ErrorKind);
    }

    [Fact]
    public void Append_writes_one_line_per_entry()
    {
        var log = new TransparencyLog(_logPath);

        log.Append(MakeEnvelope([1, 2]));
        log.Append(MakeEnvelope([3, 4]));

        var lines = File.ReadAllLines(_logPath).Where(l => !string.IsNullOrWhiteSpace(l)).ToArray();
        Assert.Equal(2, lines.Length);
    }

    [Fact]
    public void Append_entry_contains_correct_artifact_digest()
    {
        var log = new TransparencyLog(_logPath);

        var result = log.Append(MakeEnvelope());

        Assert.True(result.IsSuccess);
        Assert.Equal("sha256:aabb", result.Value.ArtifactDigest);
    }

    [Fact]
    public void Append_with_label_includes_label()
    {
        var log = new TransparencyLog(_logPath);

        var result = log.Append(MakeEnvelope(label: "v2.0"));

        Assert.True(result.IsSuccess);
        Assert.Equal("v2.0", result.Value.Label);
    }

    [Fact]
    public void Append_with_invalid_base64_signature_fails()
    {
        var log = new TransparencyLog(_logPath);
        var envelope = new SignatureEnvelope
        {
            Subject = new SubjectDescriptor
            {
                Name = "test.dll",
                Digests = new Dictionary<string, string> { ["sha256"] = "aabb" }
            },
            Signatures =
            [
                new SignatureEntry
                {
                    KeyId = "sha256:key1",
                    Algorithm = "ecdsa-p256",
                    PublicKey = "BQAA",
                    Value = "not-valid-base64!!!",
                    Timestamp = "2026-01-15T10:00:00Z"
                }
            ]
        };

        var result = log.Append(envelope);

        Assert.False(result.IsSuccess);
        Assert.Equal(TransparencyErrorKind.InvalidEnvelope, result.ErrorKind);
        Assert.Contains("base64", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }
}
