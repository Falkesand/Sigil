using Sigil.Graph;

namespace Sigil.Core.Tests.Graph;

public class GraphBuilderScanTests : IDisposable
{
    private readonly string _tempDir;

    public GraphBuilderScanTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-scan-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
        {
            Directory.Delete(_tempDir, recursive: true);
        }
    }

    private void WriteFile(string fileName, string content)
    {
        File.WriteAllText(Path.Combine(_tempDir, fileName), content);
    }

    private static string CreateSigJson(
        string artifactName = "test.dll",
        string digest = "abc123",
        string keyId = "sha256:key1")
    {
        return $$"""
        {
          "version": "1.0",
          "subject": {
            "name": "{{artifactName}}",
            "digests": {
              "sha256": "{{digest}}"
            }
          },
          "signatures": [
            {
              "keyId": "{{keyId}}",
              "algorithm": "ecdsa-p256",
              "publicKey": "AAAAAAAAAAAAAAAAAAA",
              "value": "BBBB",
              "timestamp": "2026-01-01T00:00:00Z"
            }
          ]
        }
        """;
    }

    private static string CreateManifestSigJson(
        string subjectName = "file1.txt",
        string keyId = "sha256:mkey")
    {
        return $$"""
        {
          "version": "1.0",
          "kind": "manifest",
          "subjects": [
            {
              "name": "{{subjectName}}",
              "digests": {
                "sha256": "abc"
              }
            }
          ],
          "signatures": [
            {
              "keyId": "{{keyId}}",
              "algorithm": "ecdsa-p256",
              "publicKey": "AAAAAAAAAAAAAAAAAAA",
              "value": "BBBB",
              "timestamp": "2026-01-01T00:00:00Z"
            }
          ]
        }
        """;
    }

    private static string CreateTrustJson()
    {
        return """
        {
          "version": "1.0",
          "kind": "trust-bundle",
          "metadata": {
            "name": "test",
            "created": "2026-01-01T00:00:00Z"
          },
          "keys": [
            {
              "fingerprint": "sha256:trustkey1"
            }
          ],
          "endorsements": [],
          "revocations": [],
          "identities": []
        }
        """;
    }

    private static string CreateAttJson()
    {
        // The InTotoStatement JSON that will be base64-encoded as DSSE payload
        var statementJson = """{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"test.dll","digest":{"sha256":"abc123"}}],"predicateType":"https://slsa.dev/provenance/v1","predicate":{}}""";
        var payload = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(statementJson));

        return $$"""
        {
          "payloadType": "application/vnd.in-toto+json",
          "payload": "{{payload}}",
          "signatures": [
            {
              "keyid": "sha256:attkey1",
              "sig": "CCCC",
              "algorithm": "ecdsa-p256",
              "publicKey": "AAAAAAAAAAAAAAAAAAA",
              "timestamp": "2026-01-01T00:00:00Z"
            }
          ]
        }
        """;
    }

    [Fact]
    public void ScanDirectory_missing_directory_returns_file_not_found()
    {
        var graph = new TrustGraph();
        var nonExistent = Path.Combine(_tempDir, "does-not-exist");

        var result = GraphBuilder.ScanDirectory(graph, nonExistent);

        Assert.False(result.IsSuccess);
        Assert.Equal(GraphErrorKind.FileNotFound, result.ErrorKind);
    }

    [Fact]
    public void ScanDirectory_empty_directory_returns_zero()
    {
        var graph = new TrustGraph();

        var result = GraphBuilder.ScanDirectory(graph, _tempDir);

        Assert.True(result.IsSuccess);
        Assert.Equal(0, result.Value);
    }

    [Fact]
    public void ScanDirectory_scans_sig_json_files()
    {
        var graph = new TrustGraph();
        WriteFile("myapp.sig.json", CreateSigJson(artifactName: "myapp.dll"));

        var result = GraphBuilder.ScanDirectory(graph, _tempDir);

        Assert.True(result.IsSuccess);
        Assert.Equal(1, result.Value);
        Assert.NotNull(graph.TryGetNode("artifact:myapp.dll"));
    }

    [Fact]
    public void ScanDirectory_scans_manifest_sig_json_files()
    {
        var graph = new TrustGraph();
        WriteFile("release.manifest.sig.json", CreateManifestSigJson(subjectName: "lib.dll"));

        var result = GraphBuilder.ScanDirectory(graph, _tempDir);

        Assert.True(result.IsSuccess);
        Assert.Equal(1, result.Value);
        Assert.NotNull(graph.TryGetNode("artifact:lib.dll"));
    }

    [Fact]
    public void ScanDirectory_scans_att_json_files()
    {
        var graph = new TrustGraph();
        WriteFile("build.att.json", CreateAttJson());

        var result = GraphBuilder.ScanDirectory(graph, _tempDir);

        Assert.True(result.IsSuccess);
        Assert.Equal(1, result.Value);
        Assert.NotNull(graph.TryGetNode("artifact:test.dll"));
    }

    [Fact]
    public void ScanDirectory_scans_trust_json_files()
    {
        var graph = new TrustGraph();
        WriteFile("trust.json", CreateTrustJson());

        var result = GraphBuilder.ScanDirectory(graph, _tempDir);

        Assert.True(result.IsSuccess);
        Assert.Equal(1, result.Value);
        Assert.NotNull(graph.TryGetNode("key:sha256:trustkey1"));
    }

    [Fact]
    public void ScanDirectory_skips_malformed_files()
    {
        var graph = new TrustGraph();
        WriteFile("bad.sig.json", "{ not valid json at all }}}");
        WriteFile("good.sig.json", CreateSigJson(artifactName: "good.dll"));

        var result = GraphBuilder.ScanDirectory(graph, _tempDir);

        Assert.True(result.IsSuccess);
        Assert.Equal(1, result.Value);
        Assert.NotNull(graph.TryGetNode("artifact:good.dll"));
    }

    [Fact]
    public void ScanDirectory_returns_correct_count_for_mixed_file_types()
    {
        var graph = new TrustGraph();
        WriteFile("app.sig.json", CreateSigJson(artifactName: "app.exe", keyId: "sha256:k1"));
        WriteFile("release.manifest.sig.json", CreateManifestSigJson(keyId: "sha256:k2"));
        WriteFile("build.att.json", CreateAttJson());
        WriteFile("trust.json", CreateTrustJson());

        var result = GraphBuilder.ScanDirectory(graph, _tempDir);

        Assert.True(result.IsSuccess);
        Assert.Equal(4, result.Value);
    }
}
