using Sigil.Graph;
using Sigil.Signing;

namespace Sigil.Core.Tests.Graph;

public class GraphBuilderSignatureTests
{
    private static SignatureEnvelope CreateEnvelope(
        string artifactName = "test.dll",
        string digest = "abc123",
        string keyId = "sha256:key1",
        string algorithm = "ecdsa-p256",
        string publicKey = "AAAAAAAAAAAAAAAAAAA",
        string? oidcIssuer = null,
        string? oidcIdentity = null,
        long? logIndex = null)
    {
        return new SignatureEnvelope
        {
            Subject = new SubjectDescriptor
            {
                Name = artifactName,
                Digests = new Dictionary<string, string> { ["sha256"] = digest }
            },
            Signatures =
            [
                new SignatureEntry
                {
                    KeyId = keyId,
                    Algorithm = algorithm,
                    PublicKey = publicKey,
                    Value = "BBBB",
                    Timestamp = "2026-01-01T00:00:00Z",
                    OidcIssuer = oidcIssuer,
                    OidcIdentity = oidcIdentity,
                    TransparencyLogIndex = logIndex
                }
            ]
        };
    }

    [Fact]
    public void IngestSignatureEnvelope_creates_artifact_node_from_subject()
    {
        var graph = new TrustGraph();
        var envelope = CreateEnvelope(artifactName: "myapp.exe");

        GraphBuilder.IngestSignatureEnvelope(graph, envelope);

        var node = graph.GetNode("artifact:myapp.exe");
        Assert.Equal(GraphNodeType.Artifact, node.Type);
        Assert.Equal("myapp.exe", node.Label);
    }

    [Fact]
    public void IngestSignatureEnvelope_sets_digest_properties_on_artifact()
    {
        var graph = new TrustGraph();
        var envelope = CreateEnvelope(digest: "deadbeef");

        GraphBuilder.IngestSignatureEnvelope(graph, envelope);

        var node = graph.GetNode("artifact:test.dll");
        Assert.Equal("deadbeef", node.Properties["sha256"]);
    }

    [Fact]
    public void IngestSignatureEnvelope_creates_key_node_for_signature()
    {
        var graph = new TrustGraph();
        var envelope = CreateEnvelope(keyId: "sha256:sigkey");

        GraphBuilder.IngestSignatureEnvelope(graph, envelope);

        var node = graph.GetNode("key:sha256:sigkey");
        Assert.Equal(GraphNodeType.Key, node.Type);
        Assert.Equal("sha256:sigkey", node.Label);
    }

    [Fact]
    public void IngestSignatureEnvelope_creates_signed_by_edge()
    {
        var graph = new TrustGraph();
        var envelope = CreateEnvelope(artifactName: "lib.dll", keyId: "sha256:k1");

        GraphBuilder.IngestSignatureEnvelope(graph, envelope);

        var edges = graph.GetOutgoingEdges("artifact:lib.dll");
        Assert.Single(edges);
        Assert.Equal(GraphEdgeType.SignedBy, edges[0].Type);
        Assert.Equal("key:sha256:k1", edges[0].TargetId);
    }

    [Fact]
    public void IngestSignatureEnvelope_sets_algorithm_property_on_key()
    {
        var graph = new TrustGraph();
        var envelope = CreateEnvelope(algorithm: "ecdsa-p384");

        GraphBuilder.IngestSignatureEnvelope(graph, envelope);

        var node = graph.GetNode("key:sha256:key1");
        Assert.Equal("ecdsa-p384", node.Properties["algorithm"]);
    }

    [Fact]
    public void IngestSignatureEnvelope_multiple_signatures_creates_multiple_keys_and_edges()
    {
        var graph = new TrustGraph();
        var envelope = new SignatureEnvelope
        {
            Subject = new SubjectDescriptor
            {
                Name = "multi.dll",
                Digests = new Dictionary<string, string> { ["sha256"] = "aaa" }
            },
            Signatures =
            [
                new SignatureEntry
                {
                    KeyId = "sha256:k1",
                    Algorithm = "ecdsa-p256",
                    PublicKey = "AAAAAAAAAAAAAAAAAAA",
                    Value = "sig1",
                    Timestamp = "2026-01-01T00:00:00Z"
                },
                new SignatureEntry
                {
                    KeyId = "sha256:k2",
                    Algorithm = "ecdsa-p384",
                    PublicKey = "BBBBBBBBBBBBBBBBBBB",
                    Value = "sig2",
                    Timestamp = "2026-01-01T00:00:00Z"
                }
            ]
        };

        GraphBuilder.IngestSignatureEnvelope(graph, envelope);

        Assert.NotNull(graph.TryGetNode("key:sha256:k1"));
        Assert.NotNull(graph.TryGetNode("key:sha256:k2"));
        var edges = graph.GetOutgoingEdges("artifact:multi.dll");
        Assert.Equal(2, edges.Count);
    }

    [Fact]
    public void IngestSignatureEnvelope_creates_identity_node_when_oidc_present()
    {
        var graph = new TrustGraph();
        var envelope = CreateEnvelope(
            oidcIssuer: "https://accounts.google.com",
            oidcIdentity: "alice@example.com");

        GraphBuilder.IngestSignatureEnvelope(graph, envelope);

        var node = graph.GetNode("identity:https://accounts.google.com/alice@example.com");
        Assert.Equal(GraphNodeType.Identity, node.Type);
        Assert.Equal("alice@example.com", node.Label);
    }

    [Fact]
    public void IngestSignatureEnvelope_creates_identity_bound_to_edge()
    {
        var graph = new TrustGraph();
        var envelope = CreateEnvelope(
            keyId: "sha256:oidckey",
            oidcIssuer: "https://token.actions.githubusercontent.com",
            oidcIdentity: "repo:org/repo:ref:refs/heads/main");

        GraphBuilder.IngestSignatureEnvelope(graph, envelope);

        var edges = graph.GetOutgoingEdges("key:sha256:oidckey");
        var identityEdge = edges.First(e => e.Type == GraphEdgeType.IdentityBoundTo);
        Assert.Equal("identity:https://token.actions.githubusercontent.com/repo:org/repo:ref:refs/heads/main", identityEdge.TargetId);
    }

    [Fact]
    public void IngestSignatureEnvelope_creates_log_node_when_log_index_present()
    {
        var graph = new TrustGraph();
        var envelope = CreateEnvelope(logIndex: 42);

        GraphBuilder.IngestSignatureEnvelope(graph, envelope);

        var node = graph.GetNode("log:42");
        Assert.Equal(GraphNodeType.LogRecord, node.Type);
        Assert.Equal("Log #42", node.Label);
    }

    [Fact]
    public void IngestSignatureEnvelope_creates_logged_in_edge()
    {
        var graph = new TrustGraph();
        var envelope = CreateEnvelope(keyId: "sha256:logkey", logIndex: 7);

        GraphBuilder.IngestSignatureEnvelope(graph, envelope);

        var edges = graph.GetOutgoingEdges("key:sha256:logkey");
        var logEdge = edges.First(e => e.Type == GraphEdgeType.LoggedIn);
        Assert.Equal("log:7", logEdge.TargetId);
    }

    [Fact]
    public void IngestSignatureEnvelope_deduplicates_artifact_node()
    {
        var graph = new TrustGraph();
        var envelope1 = CreateEnvelope(artifactName: "shared.dll", keyId: "sha256:k1");
        var envelope2 = CreateEnvelope(artifactName: "shared.dll", keyId: "sha256:k2");

        GraphBuilder.IngestSignatureEnvelope(graph, envelope1);
        GraphBuilder.IngestSignatureEnvelope(graph, envelope2);

        var artifactNodes = graph.AllNodes.Where(n => n.Id == "artifact:shared.dll").ToList();
        Assert.Single(artifactNodes);
        var edges = graph.GetOutgoingEdges("artifact:shared.dll");
        Assert.Equal(2, edges.Count);
    }
}
