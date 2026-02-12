using Sigil.Graph;

namespace Sigil.Core.Tests.Graph;

public class GraphQueryRevokedImpactTests
{
    [Fact]
    public void RevokedImpact_no_revocations()
    {
        var graph = BuildSignedArtifact("artifact:app.dll", "key:sha256:k1");

        var result = GraphQuery.RevokedImpact(graph);

        Assert.Empty(result);
    }

    [Fact]
    public void RevokedImpact_direct()
    {
        var graph = BuildSignedArtifact("artifact:app.dll", "key:sha256:k1");
        AddRevocation(graph, "key:sha256:k1");

        var result = GraphQuery.RevokedImpact(graph);

        Assert.Single(result);
        Assert.Equal("artifact:app.dll", result[0]);
    }

    [Fact]
    public void RevokedImpact_multiple_artifacts()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("artifact:a1", GraphNodeType.Artifact, "A1"));
        graph.AddNode(new GraphNode("artifact:a2", GraphNodeType.Artifact, "A2"));
        graph.AddNode(new GraphNode("key:sha256:k1", GraphNodeType.Key, "Key 1"));
        graph.AddEdge(new GraphEdge("artifact:a1", "key:sha256:k1", GraphEdgeType.SignedBy, "a1 signed by k1"));
        graph.AddEdge(new GraphEdge("artifact:a2", "key:sha256:k1", GraphEdgeType.SignedBy, "a2 signed by k1"));
        AddRevocation(graph, "key:sha256:k1");

        var result = GraphQuery.RevokedImpact(graph);

        Assert.Equal(2, result.Count);
        Assert.Contains("artifact:a1", result);
        Assert.Contains("artifact:a2", result);
    }

    [Fact]
    public void RevokedImpact_transitive_endorsement()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("artifact:app.dll", GraphNodeType.Artifact, "app.dll"));
        graph.AddNode(new GraphNode("key:sha256:k1", GraphNodeType.Key, "Key 1"));
        graph.AddNode(new GraphNode("key:sha256:k2", GraphNodeType.Key, "Key 2"));
        // Artifact signed by K2
        graph.AddEdge(new GraphEdge("artifact:app.dll", "key:sha256:k2", GraphEdgeType.SignedBy, "signed by K2"));
        // K2 endorsed by K1 (K2 depends on K1)
        graph.AddEdge(new GraphEdge("key:sha256:k2", "key:sha256:k1", GraphEdgeType.EndorsedBy, "K2 endorsed by K1"));
        // K1 is revoked
        AddRevocation(graph, "key:sha256:k1");

        var result = GraphQuery.RevokedImpact(graph);

        Assert.Single(result);
        Assert.Equal("artifact:app.dll", result[0]);
    }

    [Fact]
    public void RevokedImpact_deep_transitive()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("artifact:app.dll", GraphNodeType.Artifact, "app.dll"));
        graph.AddNode(new GraphNode("key:sha256:k1", GraphNodeType.Key, "Key 1"));
        graph.AddNode(new GraphNode("key:sha256:k2", GraphNodeType.Key, "Key 2"));
        graph.AddNode(new GraphNode("key:sha256:k3", GraphNodeType.Key, "Key 3"));
        // Artifact signed by K3
        graph.AddEdge(new GraphEdge("artifact:app.dll", "key:sha256:k3", GraphEdgeType.SignedBy, "signed by K3"));
        // K3 endorsed by K2
        graph.AddEdge(new GraphEdge("key:sha256:k3", "key:sha256:k2", GraphEdgeType.EndorsedBy, "K3 endorsed by K2"));
        // K2 endorsed by K1
        graph.AddEdge(new GraphEdge("key:sha256:k2", "key:sha256:k1", GraphEdgeType.EndorsedBy, "K2 endorsed by K1"));
        // K1 is revoked
        AddRevocation(graph, "key:sha256:k1");

        var result = GraphQuery.RevokedImpact(graph);

        Assert.Single(result);
        Assert.Equal("artifact:app.dll", result[0]);
    }

    [Fact]
    public void RevokedImpact_multiple_revoked_keys()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("artifact:a1", GraphNodeType.Artifact, "A1"));
        graph.AddNode(new GraphNode("artifact:a2", GraphNodeType.Artifact, "A2"));
        graph.AddNode(new GraphNode("key:sha256:k1", GraphNodeType.Key, "Key 1"));
        graph.AddNode(new GraphNode("key:sha256:k2", GraphNodeType.Key, "Key 2"));
        graph.AddEdge(new GraphEdge("artifact:a1", "key:sha256:k1", GraphEdgeType.SignedBy, "a1 signed by k1"));
        graph.AddEdge(new GraphEdge("artifact:a2", "key:sha256:k2", GraphEdgeType.SignedBy, "a2 signed by k2"));
        AddRevocation(graph, "key:sha256:k1");
        AddRevocation(graph, "key:sha256:k2");

        var result = GraphQuery.RevokedImpact(graph);

        Assert.Equal(2, result.Count);
        Assert.Contains("artifact:a1", result);
        Assert.Contains("artifact:a2", result);
    }

    [Fact]
    public void RevokedImpact_no_affected_artifacts()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("key:sha256:k1", GraphNodeType.Key, "Key 1"));
        AddRevocation(graph, "key:sha256:k1");

        var result = GraphQuery.RevokedImpact(graph);

        Assert.Empty(result);
    }

    [Fact]
    public void RevokedImpact_deduplicates()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("artifact:app.dll", GraphNodeType.Artifact, "app.dll"));
        graph.AddNode(new GraphNode("key:sha256:k1", GraphNodeType.Key, "Key 1"));
        graph.AddNode(new GraphNode("key:sha256:k2", GraphNodeType.Key, "Key 2"));
        // Artifact signed by both keys
        graph.AddEdge(new GraphEdge("artifact:app.dll", "key:sha256:k1", GraphEdgeType.SignedBy, "signed by k1"));
        graph.AddEdge(new GraphEdge("artifact:app.dll", "key:sha256:k2", GraphEdgeType.SignedBy, "signed by k2"));
        // Both keys revoked
        AddRevocation(graph, "key:sha256:k1");
        AddRevocation(graph, "key:sha256:k2");

        var result = GraphQuery.RevokedImpact(graph);

        Assert.Single(result);
        Assert.Equal("artifact:app.dll", result[0]);
    }

    private static TrustGraph BuildSignedArtifact(string artifactId, string keyId)
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode(artifactId, GraphNodeType.Artifact, artifactId));
        graph.AddNode(new GraphNode(keyId, GraphNodeType.Key, keyId));
        graph.AddEdge(new GraphEdge(artifactId, keyId, GraphEdgeType.SignedBy, "signed by"));
        return graph;
    }

    /// <summary>
    /// Adds a RevokedAt edge from the key to a revocation timestamp node.
    /// Creates the timestamp node if it does not already exist.
    /// </summary>
    private static void AddRevocation(TrustGraph graph, string keyId)
    {
        var revokeNodeId = $"revoke:{keyId}";
        graph.TryAddNode(new GraphNode(revokeNodeId, GraphNodeType.LogRecord, $"Revocation of {keyId}"));
        graph.AddEdge(new GraphEdge(keyId, revokeNodeId, GraphEdgeType.RevokedAt, "revoked"));
    }
}
