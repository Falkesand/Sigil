using System.Text.Json;
using Sigil.Signing;
using Sigil.Transparency;

namespace Sigil.Core.Tests.Transparency;

public class TransparencyLogVerifyTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _logPath;

    public TransparencyLogVerifyTests()
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

    private static SignatureEnvelope MakeEnvelope(byte[] sigBytes)
    {
        return new SignatureEnvelope
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
                    Value = Convert.ToBase64String(sigBytes),
                    Timestamp = "2026-01-15T10:00:00Z"
                }
            ]
        };
    }

    [Fact]
    public void Verify_valid_log_passes()
    {
        var log = new TransparencyLog(_logPath);
        log.Append(MakeEnvelope([1, 2, 3]));
        log.Append(MakeEnvelope([4, 5, 6]));

        var result = log.Verify();

        Assert.True(result.IsSuccess);
        Assert.Equal(2, result.Value.EntryCount);
        Assert.Equal(2, result.Value.ValidEntries);
        Assert.True(result.Value.AllEntriesValid);
        Assert.True(result.Value.CheckpointMatch);
    }

    [Fact]
    public void Verify_nonexistent_log_fails()
    {
        var log = new TransparencyLog(Path.Combine(_tempDir, "nonexistent.jsonl"));

        var result = log.Verify();

        Assert.False(result.IsSuccess);
        Assert.Equal(TransparencyErrorKind.LogNotFound, result.ErrorKind);
    }

    [Fact]
    public void Verify_tampered_entry_detects_invalid()
    {
        var log = new TransparencyLog(_logPath);
        log.Append(MakeEnvelope([1, 2, 3]));
        log.Append(MakeEnvelope([4, 5, 6]));

        // Tamper with log file: modify a field in the first entry
        var lines = File.ReadAllLines(_logPath);
        var entry = JsonSerializer.Deserialize<LogEntry>(lines[0])!;
        var tampered = new LogEntry
        {
            Index = entry.Index,
            Timestamp = entry.Timestamp,
            KeyId = "sha256:tampered",
            Algorithm = entry.Algorithm,
            ArtifactName = entry.ArtifactName,
            ArtifactDigest = entry.ArtifactDigest,
            SignatureDigest = entry.SignatureDigest,
            Label = entry.Label,
            LeafHash = entry.LeafHash
        };
        lines[0] = JsonSerializer.Serialize(tampered);
        File.WriteAllLines(_logPath, lines);

        var result = log.Verify();

        Assert.True(result.IsSuccess);
        Assert.False(result.Value.AllEntriesValid);
        Assert.Equal(1, result.Value.ValidEntries);
        Assert.NotNull(result.Value.InvalidIndices);
        Assert.Contains(0L, result.Value.InvalidIndices!);
    }

    [Fact]
    public void Verify_empty_log_passes()
    {
        File.WriteAllText(_logPath, "");
        var log = new TransparencyLog(_logPath);

        var result = log.Verify();

        Assert.True(result.IsSuccess);
        Assert.Equal(0, result.Value.EntryCount);
        Assert.True(result.Value.AllEntriesValid);
    }

    [Fact]
    public void Verify_checkpoint_mismatch_detected()
    {
        var log = new TransparencyLog(_logPath);
        log.Append(MakeEnvelope([1, 2, 3]));

        // Tamper with checkpoint
        var checkpointPath = Path.Combine(_tempDir, ".sigil.checkpoint");
        var checkpoint = new LogCheckpoint
        {
            TreeSize = 1,
            RootHash = "0000000000000000000000000000000000000000000000000000000000000000",
            Timestamp = "2026-01-15T12:00:00Z"
        };
        File.WriteAllText(checkpointPath, JsonSerializer.Serialize(checkpoint));

        var result = log.Verify();

        Assert.True(result.IsSuccess);
        Assert.False(result.Value.CheckpointMatch);
    }

    [Fact]
    public void Verify_no_checkpoint_still_passes()
    {
        var log = new TransparencyLog(_logPath);
        log.Append(MakeEnvelope([1, 2, 3]));

        // Delete checkpoint
        var checkpointPath = Path.Combine(_tempDir, ".sigil.checkpoint");
        if (File.Exists(checkpointPath))
            File.Delete(checkpointPath);

        var result = log.Verify();

        Assert.True(result.IsSuccess);
        Assert.True(result.Value.AllEntriesValid);
        Assert.True(result.Value.CheckpointMatch);
    }

    [Fact]
    public void Verify_computed_root_hash_is_set()
    {
        var log = new TransparencyLog(_logPath);
        log.Append(MakeEnvelope([1, 2, 3]));

        var result = log.Verify();

        Assert.True(result.IsSuccess);
        Assert.NotEmpty(result.Value.ComputedRootHash);
        Assert.Equal(64, result.Value.ComputedRootHash.Length); // SHA-256 hex = 64 chars
    }

    [Fact]
    public void Verify_malformed_json_line_skipped_and_valid_entries_still_read()
    {
        var log = new TransparencyLog(_logPath);
        log.Append(MakeEnvelope([1, 2, 3]));
        log.Append(MakeEnvelope([4, 5, 6]));

        // Insert a malformed JSON line between the two valid entries
        var lines = File.ReadAllLines(_logPath).ToList();
        lines.Insert(1, "this is not valid json!!!");
        File.WriteAllLines(_logPath, lines);

        var result = log.Verify();

        // ReadAllEntries skips malformed lines, so 2 valid entries are still read
        Assert.True(result.IsSuccess);
        Assert.Equal(2, result.Value.EntryCount);
        Assert.True(result.Value.AllEntriesValid);
    }

    [Fact]
    public void Verify_malformed_json_replacing_valid_entry_detected()
    {
        var log = new TransparencyLog(_logPath);
        log.Append(MakeEnvelope([1, 2, 3]));
        log.Append(MakeEnvelope([4, 5, 6]));

        // Replace a valid entry with garbage — checkpoint tree size won't match
        var lines = File.ReadAllLines(_logPath);
        lines[0] = "this is not valid json!!!";
        File.WriteAllLines(_logPath, lines);

        var result = log.Verify();

        // Only 1 valid entry remains but checkpoint expects 2
        Assert.True(result.IsSuccess);
        Assert.Equal(1, result.Value.EntryCount);
        Assert.False(result.Value.CheckpointMatch);
    }
}
