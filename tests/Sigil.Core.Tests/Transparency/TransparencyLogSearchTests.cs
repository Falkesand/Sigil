using Sigil.Signing;
using Sigil.Transparency;

namespace Sigil.Core.Tests.Transparency;

public class TransparencyLogSearchTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _logPath;

    public TransparencyLogSearchTests()
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

    private static SignatureEnvelope MakeEnvelope(byte[] sigBytes, string keyId = "sha256:key1", string name = "test.dll")
    {
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
                    KeyId = keyId,
                    Algorithm = "ecdsa-p256",
                    PublicKey = "BQAA",
                    Value = Convert.ToBase64String(sigBytes),
                    Timestamp = "2026-01-15T10:00:00Z"
                }
            ]
        };
    }

    [Fact]
    public void Search_by_key_id()
    {
        var log = new TransparencyLog(_logPath);
        log.Append(MakeEnvelope([1, 2], keyId: "sha256:keyA"));
        log.Append(MakeEnvelope([3, 4], keyId: "sha256:keyB"));
        log.Append(MakeEnvelope([5, 6], keyId: "sha256:keyA"));

        var result = log.Search(keyId: "sha256:keyA");

        Assert.True(result.IsSuccess);
        Assert.Equal(2, result.Value.Count);
    }

    [Fact]
    public void Search_by_artifact_name()
    {
        var log = new TransparencyLog(_logPath);
        log.Append(MakeEnvelope([1, 2], name: "lib.dll"));
        log.Append(MakeEnvelope([3, 4], name: "app.exe"));

        var result = log.Search(artifactName: "app.exe");

        Assert.True(result.IsSuccess);
        Assert.Single(result.Value);
        Assert.Equal("app.exe", result.Value[0].ArtifactName);
    }

    [Fact]
    public void Search_by_digest()
    {
        var log = new TransparencyLog(_logPath);
        log.Append(MakeEnvelope([1, 2]));

        var entry = log.Search().Value[0];
        var result = log.Search(digest: entry.SignatureDigest);

        Assert.True(result.IsSuccess);
        Assert.Single(result.Value);
    }

    [Fact]
    public void Search_no_results()
    {
        var log = new TransparencyLog(_logPath);
        log.Append(MakeEnvelope([1, 2]));

        var result = log.Search(keyId: "sha256:nonexistent");

        Assert.True(result.IsSuccess);
        Assert.Empty(result.Value);
    }

    [Fact]
    public void Search_combined_filters()
    {
        var log = new TransparencyLog(_logPath);
        log.Append(MakeEnvelope([1, 2], keyId: "sha256:keyA", name: "lib.dll"));
        log.Append(MakeEnvelope([3, 4], keyId: "sha256:keyA", name: "app.exe"));
        log.Append(MakeEnvelope([5, 6], keyId: "sha256:keyB", name: "lib.dll"));

        var result = log.Search(keyId: "sha256:keyA", artifactName: "lib.dll");

        Assert.True(result.IsSuccess);
        Assert.Single(result.Value);
    }

    [Fact]
    public void Search_nonexistent_log_fails()
    {
        var log = new TransparencyLog(Path.Combine(_tempDir, "nonexistent.jsonl"));

        var result = log.Search(keyId: "sha256:key1");

        Assert.False(result.IsSuccess);
        Assert.Equal(TransparencyErrorKind.LogNotFound, result.ErrorKind);
    }
}
