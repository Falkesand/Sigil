using System.Security.Cryptography;
using System.Text.Json;
using Sigil.Crypto;
using Sigil.Graph;
using Sigil.Keys;

namespace Sigil.Cli.Tests.Commands;

public class ImpactCommandTests : IDisposable
{
    private readonly string _tempDir;

    public ImpactCommandTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-impact-cli-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
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

    private static string CreateTrustJsonWithEndorsement(
        string endorser = "sha256:root",
        string endorsed = "sha256:child")
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
            { "fingerprint": "{{endorser}}" },
            { "fingerprint": "{{endorsed}}" }
          ],
          "endorsements": [
            {
              "endorser": "{{endorser}}",
              "endorsed": "{{endorsed}}",
              "timestamp": "2026-01-01T00:00:00Z"
            }
          ],
          "revocations": [],
          "identities": []
        }
        """;
    }

    private static string CreateGraphJsonFromBuilder(string keyId = "sha256:testkey1")
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("artifact:test.dll", GraphNodeType.Artifact, "test.dll"));
        graph.AddNode(new GraphNode($"key:{keyId}", GraphNodeType.Key, keyId));
        graph.AddEdge(new GraphEdge("artifact:test.dll", $"key:{keyId}", GraphEdgeType.SignedBy, "signed by"));

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

    private static string CreateGraphJsonWithEndorsement()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("artifact:downstream.dll", GraphNodeType.Artifact, "downstream.dll"));
        graph.AddNode(new GraphNode("key:sha256:root", GraphNodeType.Key, "root-key"));
        graph.AddNode(new GraphNode("key:sha256:child", GraphNodeType.Key, "child-key"));
        graph.AddEdge(new GraphEdge("key:sha256:child", "key:sha256:root", GraphEdgeType.EndorsedBy, "endorsed by"));
        graph.AddEdge(new GraphEdge("artifact:downstream.dll", "key:sha256:child", GraphEdgeType.SignedBy, "signed by"));

        var result = GraphSerializer.Serialize(graph);
        return result.Value;
    }

    // --- No args ---

    [Fact]
    public async Task Impact_no_args_shows_error()
    {
        var result = await CommandTestHelper.InvokeAsync("impact");

        Assert.Equal(1, result.ExitCode);
        Assert.Contains("--fingerprint", result.StdErr + result.StdOut);
    }

    // --- --fingerprint + --scan ---

    [Fact]
    public async Task Impact_fingerprint_scan_text_output()
    {
        var scanDir = Path.Combine(_tempDir, "scan");
        Directory.CreateDirectory(scanDir);
        File.WriteAllText(Path.Combine(scanDir, "app.sig.json"), CreateSigJson());

        var result = await CommandTestHelper.InvokeAsync(
            "impact", "--fingerprint", "sha256:testkey1", "--scan", scanDir);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Key Compromise Impact Report", result.StdOut);
        Assert.Contains("sha256:testkey1", result.StdOut);
        Assert.Contains("artifact:test.dll", result.StdOut);
    }

    // --- --fingerprint + --graph ---

    [Fact]
    public async Task Impact_fingerprint_graph_text_output()
    {
        var graphPath = Path.Combine(_tempDir, "graph.json");
        File.WriteAllText(graphPath, CreateGraphJsonFromBuilder());

        var result = await CommandTestHelper.InvokeAsync(
            "impact", "--fingerprint", "sha256:testkey1", "--graph", graphPath);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Key Compromise Impact Report", result.StdOut);
        Assert.Contains("artifact:test.dll", result.StdOut);
    }

    // --- --format json ---

    [Fact]
    public async Task Impact_format_json_produces_valid_json()
    {
        var graphPath = Path.Combine(_tempDir, "graph.json");
        File.WriteAllText(graphPath, CreateGraphJsonFromBuilder());

        var result = await CommandTestHelper.InvokeAsync(
            "impact", "--fingerprint", "sha256:testkey1", "--graph", graphPath, "--format", "json");

        Assert.Equal(0, result.ExitCode);
        var doc = JsonDocument.Parse(result.StdOut);
        Assert.Equal("sha256:testkey1", doc.RootElement.GetProperty("fingerprint").GetString());
    }

    // --- --output ---

    [Fact]
    public async Task Impact_output_writes_to_file()
    {
        var graphPath = Path.Combine(_tempDir, "graph.json");
        File.WriteAllText(graphPath, CreateGraphJsonFromBuilder());
        var outputPath = Path.Combine(_tempDir, "report.txt");

        var result = await CommandTestHelper.InvokeAsync(
            "impact", "--fingerprint", "sha256:testkey1", "--graph", graphPath, "--output", outputPath);

        Assert.Equal(0, result.ExitCode);
        Assert.True(File.Exists(outputPath));
        var content = File.ReadAllText(outputPath);
        Assert.Contains("Key Compromise Impact Report", content);
        Assert.Contains("Impact report written to", result.StdOut);
    }

    // --- --key with PEM ---

    [Fact]
    public async Task Impact_key_pem_resolves_fingerprint()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var spki = ecdsa.ExportSubjectPublicKeyInfo();
        var pemContent = ecdsa.ExportSubjectPublicKeyInfoPem();
        var fingerprint = KeyFingerprint.Compute(spki).Value;

        var pemPath = Path.Combine(_tempDir, "key.pub.pem");
        File.WriteAllText(pemPath, pemContent);

        var graphPath = Path.Combine(_tempDir, "graph.json");
        File.WriteAllText(graphPath, CreateGraphJsonFromBuilder(fingerprint));

        var result = await CommandTestHelper.InvokeAsync(
            "impact", "--key", pemPath, "--graph", graphPath);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Key Compromise Impact Report", result.StdOut);
        Assert.Contains(fingerprint, result.StdOut);
    }

    // --- Missing --scan and --graph ---

    [Fact]
    public async Task Impact_missing_scan_and_graph_errors()
    {
        var result = await CommandTestHelper.InvokeAsync(
            "impact", "--fingerprint", "sha256:testkey1");

        Assert.Equal(1, result.ExitCode);
        Assert.Contains("--scan", result.StdErr);
        Assert.Contains("--graph", result.StdErr);
    }

    // --- Both --scan and --graph ---

    [Fact]
    public async Task Impact_both_scan_and_graph_errors()
    {
        var scanDir = Path.Combine(_tempDir, "scan");
        Directory.CreateDirectory(scanDir);
        var graphPath = Path.Combine(_tempDir, "graph.json");
        File.WriteAllText(graphPath, CreateGraphJsonFromBuilder());

        var result = await CommandTestHelper.InvokeAsync(
            "impact", "--fingerprint", "sha256:testkey1", "--scan", scanDir, "--graph", graphPath);

        Assert.Equal(1, result.ExitCode);
        Assert.Contains("either --scan or --graph", result.StdErr);
    }

    // --- Both --fingerprint and --key ---

    [Fact]
    public async Task Impact_both_fingerprint_and_key_errors()
    {
        var pemPath = Path.Combine(_tempDir, "key.pem");
        File.WriteAllText(pemPath, "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n-----END PUBLIC KEY-----");

        var result = await CommandTestHelper.InvokeAsync(
            "impact", "--fingerprint", "sha256:testkey1", "--key", pemPath, "--scan", _tempDir);

        Assert.Equal(1, result.ExitCode);
        Assert.Contains("either --fingerprint or --key", result.StdErr);
    }

    // --- Neither --fingerprint nor --key ---

    [Fact]
    public async Task Impact_neither_fingerprint_nor_key_errors()
    {
        var result = await CommandTestHelper.InvokeAsync(
            "impact", "--scan", _tempDir);

        Assert.Equal(1, result.ExitCode);
        Assert.Contains("--fingerprint", result.StdErr);
        Assert.Contains("--key", result.StdErr);
    }

    // --- Missing PEM file ---

    [Fact]
    public async Task Impact_missing_pem_file_errors()
    {
        var nonExistent = Path.Combine(_tempDir, "nonexistent.pem");

        var result = await CommandTestHelper.InvokeAsync(
            "impact", "--key", nonExistent, "--scan", _tempDir);

        Assert.Equal(1, result.ExitCode);
        Assert.Contains("PEM file not found", result.StdErr);
    }

    // --- Missing graph file ---

    [Fact]
    public async Task Impact_missing_graph_file_errors()
    {
        var nonExistent = Path.Combine(_tempDir, "nonexistent.json");

        var result = await CommandTestHelper.InvokeAsync(
            "impact", "--fingerprint", "sha256:testkey1", "--graph", nonExistent);

        Assert.Equal(1, result.ExitCode);
        Assert.Contains("Graph file not found", result.StdErr);
    }

    // --- Key not found in graph ---

    [Fact]
    public async Task Impact_key_not_found_in_graph_errors()
    {
        var graphPath = Path.Combine(_tempDir, "graph.json");
        File.WriteAllText(graphPath, CreateGraphJsonFromBuilder());

        var result = await CommandTestHelper.InvokeAsync(
            "impact", "--fingerprint", "sha256:nonexistent", "--graph", graphPath);

        Assert.Equal(1, result.ExitCode);
        Assert.Contains("not found", result.StdErr);
    }

    // --- Revoked key shows details ---

    [Fact]
    public async Task Impact_revoked_key_shows_revocation_details()
    {
        var graphPath = Path.Combine(_tempDir, "graph.json");
        File.WriteAllText(graphPath, CreateGraphJsonWithRevocation());

        var result = await CommandTestHelper.InvokeAsync(
            "impact", "--fingerprint", "sha256:testkey1", "--graph", graphPath);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("REVOKED", result.StdOut);
        Assert.Contains("compromised", result.StdOut);
    }

    // --- Endorsement chain shows transitive impact ---

    [Fact]
    public async Task Impact_endorsement_chain_shows_transitive()
    {
        var graphPath = Path.Combine(_tempDir, "graph.json");
        File.WriteAllText(graphPath, CreateGraphJsonWithEndorsement());

        var result = await CommandTestHelper.InvokeAsync(
            "impact", "--fingerprint", "sha256:root", "--graph", graphPath);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Transitive Impact", result.StdOut);
        Assert.Contains("artifact:downstream.dll", result.StdOut);
    }

    // --- Empty directory scan, key not found ---

    [Fact]
    public async Task Impact_empty_scan_key_not_found()
    {
        var emptyDir = Path.Combine(_tempDir, "empty");
        Directory.CreateDirectory(emptyDir);

        var result = await CommandTestHelper.InvokeAsync(
            "impact", "--fingerprint", "sha256:testkey1", "--scan", emptyDir);

        Assert.Equal(1, result.ExitCode);
        Assert.Contains("not found", result.StdErr);
    }

    // --- Invalid format ---

    [Fact]
    public async Task Impact_invalid_format_errors()
    {
        var graphPath = Path.Combine(_tempDir, "graph.json");
        File.WriteAllText(graphPath, CreateGraphJsonFromBuilder());

        var result = await CommandTestHelper.InvokeAsync(
            "impact", "--fingerprint", "sha256:testkey1", "--graph", graphPath, "--format", "xml");

        Assert.Equal(1, result.ExitCode);
        Assert.Contains("Unknown format", result.StdErr);
    }
}
