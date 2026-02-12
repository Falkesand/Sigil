using Sigil.Graph;

namespace Sigil.Cli.Tests.Commands;

public class GraphCommandTests : IDisposable
{
    private readonly string _tempDir;

    public GraphCommandTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-graph-cli-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    private string CreateFile(string relativePath, string content)
    {
        var fullPath = Path.Combine(_tempDir, relativePath.Replace('/', Path.DirectorySeparatorChar));
        var dir = Path.GetDirectoryName(fullPath)!;
        Directory.CreateDirectory(dir);
        File.WriteAllText(fullPath, content);
        return fullPath;
    }

    private static string CreateSigJson(
        string artifactName = "test.dll",
        string digest = "abc123",
        string keyId = "sha256:testkey1")
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

    private static string CreateTrustJsonWithRevocation(
        string fingerprint = "sha256:testkey1")
    {
        return $$"""
        {
          "version": "1.0",
          "kind": "trust-bundle",
          "metadata": {
            "name": "test",
            "created": "2026-01-01T00:00:00Z"
          },
          "keys": [
            {
              "fingerprint": "{{fingerprint}}"
            }
          ],
          "endorsements": [],
          "revocations": [
            {
              "fingerprint": "{{fingerprint}}",
              "revokedAt": "2026-01-01T00:00:00Z",
              "reason": "compromised"
            }
          ],
          "identities": []
        }
        """;
    }

    private static string CreateGraphJsonFromBuilder()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("artifact:test.dll", GraphNodeType.Artifact, "test.dll"));
        graph.AddNode(new GraphNode("key:sha256:testkey1", GraphNodeType.Key, "sha256:testkey1"));
        graph.AddEdge(new GraphEdge("artifact:test.dll", "key:sha256:testkey1", GraphEdgeType.SignedBy, "signed by"));

        var result = GraphSerializer.Serialize(graph);
        return result.Value;
    }

    private static string CreateGraphJsonWithRevocation()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("artifact:test.dll", GraphNodeType.Artifact, "test.dll"));
        graph.AddNode(new GraphNode("key:sha256:testkey1", GraphNodeType.Key, "sha256:testkey1"));
        graph.AddEdge(new GraphEdge("artifact:test.dll", "key:sha256:testkey1", GraphEdgeType.SignedBy, "signed by"));
        var revokedEdge = new GraphEdge("key:sha256:testkey1", "key:sha256:testkey1", GraphEdgeType.RevokedAt, "revoked");
        revokedEdge.Properties["revokedAt"] = "2026-01-01T00:00:00Z";
        revokedEdge.Properties["reason"] = "compromised";
        graph.AddEdge(revokedEdge);

        var result = GraphSerializer.Serialize(graph);
        return result.Value;
    }

    // --- graph build tests ---

    [Fact]
    public async Task Graph_build_missing_dir_fails()
    {
        var nonExistent = Path.Combine(_tempDir, "nonexistent");

        var result = await CommandTestHelper.InvokeAsync("graph", "build", "--scan", nonExistent);

        Assert.Equal(1, result.ExitCode);
        Assert.Contains("Error", result.StdErr);
    }

    [Fact]
    public async Task Graph_build_empty_dir_produces_graph()
    {
        var emptyDir = Path.Combine(_tempDir, "empty");
        Directory.CreateDirectory(emptyDir);
        var outputPath = Path.Combine(_tempDir, "graph.json");

        var result = await CommandTestHelper.InvokeAsync("graph", "build", "--scan", emptyDir, "--output", outputPath);

        Assert.Equal(0, result.ExitCode);
        Assert.True(File.Exists(outputPath));
        Assert.Contains("Graph written to", result.StdOut);
    }

    [Fact]
    public async Task Graph_build_scans_sig_json()
    {
        var scanDir = Path.Combine(_tempDir, "scan");
        Directory.CreateDirectory(scanDir);
        File.WriteAllText(Path.Combine(scanDir, "app.sig.json"), CreateSigJson(artifactName: "app.dll"));
        var outputPath = Path.Combine(_tempDir, "graph.json");

        var result = await CommandTestHelper.InvokeAsync("graph", "build", "--scan", scanDir, "--output", outputPath);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("1 file(s)", result.StdOut);

        // Verify the output graph contains nodes
        var json = File.ReadAllText(outputPath);
        var graphResult = GraphSerializer.Deserialize(json);
        Assert.True(graphResult.IsSuccess);
        Assert.True(graphResult.Value.NodeCount > 0);
    }

    [Fact]
    public async Task Graph_build_default_output()
    {
        var scanDir = Path.Combine(_tempDir, "scan");
        Directory.CreateDirectory(scanDir);
        File.WriteAllText(Path.Combine(scanDir, "app.sig.json"), CreateSigJson());
        var outputPath = Path.Combine(_tempDir, "default-out.json");

        var result = await CommandTestHelper.InvokeAsync("graph", "build", "--scan", scanDir, "--output", outputPath);

        Assert.Equal(0, result.ExitCode);
        Assert.True(File.Exists(outputPath));
    }

    // --- graph query tests ---

    [Fact]
    public async Task Graph_query_chain()
    {
        var graphPath = Path.Combine(_tempDir, "graph.json");
        File.WriteAllText(graphPath, CreateGraphJsonFromBuilder());

        var result = await CommandTestHelper.InvokeAsync(
            "graph", "query", "--graph", graphPath, "--artifact", "test.dll", "--chain");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Trust chain for artifact:test.dll:", result.StdOut);
        Assert.Contains("artifact:test.dll", result.StdOut);
        Assert.Contains("key:sha256:testkey1", result.StdOut);
    }

    [Fact]
    public async Task Graph_query_revoked_impact()
    {
        var graphPath = Path.Combine(_tempDir, "graph.json");
        File.WriteAllText(graphPath, CreateGraphJsonWithRevocation());

        var result = await CommandTestHelper.InvokeAsync(
            "graph", "query", "--graph", graphPath, "--revoked", "--impact");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Revoked key impact analysis:", result.StdOut);
        Assert.Contains("artifact:test.dll", result.StdOut);
    }

    [Fact]
    public async Task Graph_query_signed_by()
    {
        var graphPath = Path.Combine(_tempDir, "graph.json");
        File.WriteAllText(graphPath, CreateGraphJsonFromBuilder());

        var result = await CommandTestHelper.InvokeAsync(
            "graph", "query", "--graph", graphPath, "--key", "sha256:testkey1", "--signed-by");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Artifacts signed by key:sha256:testkey1:", result.StdOut);
        Assert.Contains("artifact:test.dll", result.StdOut);
    }

    [Fact]
    public async Task Graph_query_missing_graph_file_fails_with_message()
    {
        var nonExistent = Path.Combine(_tempDir, "nonexistent.json");

        var result = await CommandTestHelper.InvokeAsync(
            "graph", "query", "--graph", nonExistent, "--revoked", "--impact");

        Assert.Equal(1, result.ExitCode);
        Assert.Contains("Graph file not found", result.StdErr);
        Assert.Contains("nonexistent.json", result.StdErr);
    }

    // --- graph export tests ---

    [Fact]
    public async Task Graph_export_missing_graph_file_fails_with_message()
    {
        var nonExistent = Path.Combine(_tempDir, "nonexistent.json");

        var result = await CommandTestHelper.InvokeAsync(
            "graph", "export", "--graph", nonExistent, "--format", "dot");

        Assert.Equal(1, result.ExitCode);
        Assert.Contains("Graph file not found", result.StdErr);
        Assert.Contains("nonexistent.json", result.StdErr);
    }


    [Fact]
    public async Task Graph_export_dot()
    {
        var graphPath = Path.Combine(_tempDir, "graph.json");
        File.WriteAllText(graphPath, CreateGraphJsonFromBuilder());

        var result = await CommandTestHelper.InvokeAsync(
            "graph", "export", "--graph", graphPath, "--format", "dot");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("digraph TrustGraph {", result.StdOut);
        Assert.Contains("rankdir=LR;", result.StdOut);
    }

    [Fact]
    public async Task Graph_export_json()
    {
        var graphPath = Path.Combine(_tempDir, "graph.json");
        File.WriteAllText(graphPath, CreateGraphJsonFromBuilder());

        var result = await CommandTestHelper.InvokeAsync(
            "graph", "export", "--graph", graphPath, "--format", "json");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("\"nodes\"", result.StdOut);
        Assert.Contains("\"edges\"", result.StdOut);
    }

    [Fact]
    public async Task Graph_export_to_file()
    {
        var graphPath = Path.Combine(_tempDir, "graph.json");
        File.WriteAllText(graphPath, CreateGraphJsonFromBuilder());
        var exportPath = Path.Combine(_tempDir, "export.dot");

        var result = await CommandTestHelper.InvokeAsync(
            "graph", "export", "--graph", graphPath, "--format", "dot", "--output", exportPath);

        Assert.Equal(0, result.ExitCode);
        Assert.True(File.Exists(exportPath));
        var content = File.ReadAllText(exportPath);
        Assert.Contains("digraph TrustGraph {", content);
        Assert.Contains("Exported graph to", result.StdOut);
    }

    [Fact]
    public async Task Graph_export_unknown_format_fails()
    {
        var graphPath = Path.Combine(_tempDir, "graph.json");
        File.WriteAllText(graphPath, CreateGraphJsonFromBuilder());

        var result = await CommandTestHelper.InvokeAsync(
            "graph", "export", "--graph", graphPath, "--format", "xml");

        Assert.Equal(1, result.ExitCode);
        Assert.Contains("Unknown format", result.StdErr);
    }
}
