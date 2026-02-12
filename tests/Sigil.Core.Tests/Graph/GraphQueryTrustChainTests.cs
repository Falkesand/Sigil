using Sigil.Graph;

namespace Sigil.Core.Tests.Graph;

public class GraphQueryTrustChainTests
{
    [Fact]
    public void TrustChain_artifact_to_key()
    {
        var graph = BuildSignedArtifact("artifact:app.dll", "key:sha256:k1");

        var result = GraphQuery.TrustChain(graph, "artifact:app.dll");

        Assert.True(result.IsSuccess);
        Assert.Equal(["artifact:app.dll", "key:sha256:k1"], result.Value);
    }

    [Fact]
    public void TrustChain_artifact_to_endorser()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("artifact:app.dll", GraphNodeType.Artifact, "app.dll"));
        graph.AddNode(new GraphNode("key:sha256:k1", GraphNodeType.Key, "Key 1"));
        graph.AddNode(new GraphNode("key:sha256:k2", GraphNodeType.Key, "Key 2"));
        graph.AddEdge(new GraphEdge("artifact:app.dll", "key:sha256:k1", GraphEdgeType.SignedBy, "signed by K1"));
        graph.AddEdge(new GraphEdge("key:sha256:k1", "key:sha256:k2", GraphEdgeType.EndorsedBy, "endorsed by K2"));

        var result = GraphQuery.TrustChain(graph, "artifact:app.dll");

        Assert.True(result.IsSuccess);
        Assert.Contains("artifact:app.dll", result.Value);
        Assert.Contains("key:sha256:k1", result.Value);
        Assert.Contains("key:sha256:k2", result.Value);
        Assert.Equal(3, result.Value.Count);
    }

    [Fact]
    public void TrustChain_ignores_non_trust_edges()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("artifact:app.dll", GraphNodeType.Artifact, "app.dll"));
        graph.AddNode(new GraphNode("key:sha256:k1", GraphNodeType.Key, "Key 1"));
        graph.AddNode(new GraphNode("log:entry1", GraphNodeType.LogRecord, "Log Entry"));
        graph.AddEdge(new GraphEdge("artifact:app.dll", "key:sha256:k1", GraphEdgeType.SignedBy, "signed by K1"));
        graph.AddEdge(new GraphEdge("key:sha256:k1", "log:entry1", GraphEdgeType.LoggedIn, "logged in"));

        var result = GraphQuery.TrustChain(graph, "artifact:app.dll");

        Assert.True(result.IsSuccess);
        Assert.Contains("artifact:app.dll", result.Value);
        Assert.Contains("key:sha256:k1", result.Value);
        Assert.DoesNotContain("log:entry1", result.Value);
        Assert.Equal(2, result.Value.Count);
    }

    [Fact]
    public void TrustChain_node_not_found()
    {
        var graph = new TrustGraph();

        var result = GraphQuery.TrustChain(graph, "nonexistent");

        Assert.False(result.IsSuccess);
        Assert.Equal(GraphErrorKind.NodeNotFound, result.ErrorKind);
    }

    [Fact]
    public void TrustChain_isolated_node()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("artifact:solo", GraphNodeType.Artifact, "solo"));

        var result = GraphQuery.TrustChain(graph, "artifact:solo");

        Assert.True(result.IsSuccess);
        Assert.Single(result.Value);
        Assert.Equal("artifact:solo", result.Value[0]);
    }

    [Fact]
    public void TrustChain_multiple_signers()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("artifact:app.dll", GraphNodeType.Artifact, "app.dll"));
        graph.AddNode(new GraphNode("key:sha256:k1", GraphNodeType.Key, "Key 1"));
        graph.AddNode(new GraphNode("key:sha256:k2", GraphNodeType.Key, "Key 2"));
        graph.AddEdge(new GraphEdge("artifact:app.dll", "key:sha256:k1", GraphEdgeType.SignedBy, "signed by K1"));
        graph.AddEdge(new GraphEdge("artifact:app.dll", "key:sha256:k2", GraphEdgeType.SignedBy, "signed by K2"));

        var result = GraphQuery.TrustChain(graph, "artifact:app.dll");

        Assert.True(result.IsSuccess);
        Assert.Contains("artifact:app.dll", result.Value);
        Assert.Contains("key:sha256:k1", result.Value);
        Assert.Contains("key:sha256:k2", result.Value);
        Assert.Equal(3, result.Value.Count);
    }

    [Fact]
    public void TrustChain_deep_chain()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("artifact:app.dll", GraphNodeType.Artifact, "app.dll"));
        graph.AddNode(new GraphNode("key:sha256:k1", GraphNodeType.Key, "Key 1"));
        graph.AddNode(new GraphNode("key:sha256:k2", GraphNodeType.Key, "Key 2"));
        graph.AddNode(new GraphNode("key:sha256:k3", GraphNodeType.Key, "Key 3"));
        graph.AddEdge(new GraphEdge("artifact:app.dll", "key:sha256:k1", GraphEdgeType.SignedBy, "signed by K1"));
        graph.AddEdge(new GraphEdge("key:sha256:k1", "key:sha256:k2", GraphEdgeType.EndorsedBy, "endorsed by K2"));
        graph.AddEdge(new GraphEdge("key:sha256:k2", "key:sha256:k3", GraphEdgeType.EndorsedBy, "endorsed by K3"));

        var result = GraphQuery.TrustChain(graph, "artifact:app.dll");

        Assert.True(result.IsSuccess);
        Assert.Contains("artifact:app.dll", result.Value);
        Assert.Contains("key:sha256:k1", result.Value);
        Assert.Contains("key:sha256:k2", result.Value);
        Assert.Contains("key:sha256:k3", result.Value);
        Assert.Equal(4, result.Value.Count);
    }

    [Fact]
    public void TrustChain_handles_cycle()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("key:sha256:k1", GraphNodeType.Key, "Key 1"));
        graph.AddNode(new GraphNode("key:sha256:k2", GraphNodeType.Key, "Key 2"));
        graph.AddEdge(new GraphEdge("key:sha256:k1", "key:sha256:k2", GraphEdgeType.EndorsedBy, "k1 endorsed by k2"));
        graph.AddEdge(new GraphEdge("key:sha256:k2", "key:sha256:k1", GraphEdgeType.EndorsedBy, "k2 endorsed by k1"));

        var result = GraphQuery.TrustChain(graph, "key:sha256:k1");

        Assert.True(result.IsSuccess);
        Assert.Contains("key:sha256:k1", result.Value);
        Assert.Contains("key:sha256:k2", result.Value);
        Assert.Equal(2, result.Value.Count);
    }

    private static TrustGraph BuildSignedArtifact(string artifactId, string keyId)
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode(artifactId, GraphNodeType.Artifact, artifactId));
        graph.AddNode(new GraphNode(keyId, GraphNodeType.Key, keyId));
        graph.AddEdge(new GraphEdge(artifactId, keyId, GraphEdgeType.SignedBy, "signed by"));
        return graph;
    }
}
