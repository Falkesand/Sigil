using Sigil.Graph;

namespace Sigil.Core.Tests.Graph;

public class GraphQuerySignedByTests
{
    [Fact]
    public void SignedBy_finds_artifact()
    {
        var graph = BuildSignedGraph("artifact:app.dll", "key:sha256:k1");

        var result = GraphQuery.SignedBy(graph, "key:sha256:k1");

        Assert.True(result.IsSuccess);
        Assert.Single(result.Value);
        Assert.Equal("artifact:app.dll", result.Value[0]);
    }

    [Fact]
    public void SignedBy_finds_multiple_artifacts()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("artifact:a1", GraphNodeType.Artifact, "A1"));
        graph.AddNode(new GraphNode("artifact:a2", GraphNodeType.Artifact, "A2"));
        graph.AddNode(new GraphNode("key:sha256:k1", GraphNodeType.Key, "Key 1"));
        graph.AddEdge(new GraphEdge("artifact:a1", "key:sha256:k1", GraphEdgeType.SignedBy, "a1 signed by k1"));
        graph.AddEdge(new GraphEdge("artifact:a2", "key:sha256:k1", GraphEdgeType.SignedBy, "a2 signed by k1"));

        var result = GraphQuery.SignedBy(graph, "key:sha256:k1");

        Assert.True(result.IsSuccess);
        Assert.Equal(2, result.Value.Count);
        Assert.Contains("artifact:a1", result.Value);
        Assert.Contains("artifact:a2", result.Value);
    }

    [Fact]
    public void SignedBy_key_not_found()
    {
        var graph = new TrustGraph();

        var result = GraphQuery.SignedBy(graph, "key:sha256:missing");

        Assert.False(result.IsSuccess);
        Assert.Equal(GraphErrorKind.NodeNotFound, result.ErrorKind);
    }

    [Fact]
    public void SignedBy_no_artifacts()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("key:sha256:k1", GraphNodeType.Key, "Key 1"));

        var result = GraphQuery.SignedBy(graph, "key:sha256:k1");

        Assert.True(result.IsSuccess);
        Assert.Empty(result.Value);
    }

    [Fact]
    public void SignedBy_ignores_other_edge_types()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("key:sha256:k1", GraphNodeType.Key, "Key 1"));
        graph.AddNode(new GraphNode("key:sha256:k2", GraphNodeType.Key, "Key 2"));
        graph.AddEdge(new GraphEdge("key:sha256:k2", "key:sha256:k1", GraphEdgeType.EndorsedBy, "endorsed by k1"));

        var result = GraphQuery.SignedBy(graph, "key:sha256:k1");

        Assert.True(result.IsSuccess);
        Assert.Empty(result.Value);
    }

    [Fact]
    public void SignedBy_includes_attestation_nodes()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("attestation:vuln-scan", GraphNodeType.Attestation, "Vulnerability Scan"));
        graph.AddNode(new GraphNode("key:sha256:k1", GraphNodeType.Key, "Key 1"));
        graph.AddEdge(new GraphEdge("attestation:vuln-scan", "key:sha256:k1", GraphEdgeType.SignedBy, "attested by k1"));

        var result = GraphQuery.SignedBy(graph, "key:sha256:k1");

        Assert.True(result.IsSuccess);
        Assert.Single(result.Value);
        Assert.Equal("attestation:vuln-scan", result.Value[0]);
    }

    private static TrustGraph BuildSignedGraph(string artifactId, string keyId)
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode(artifactId, GraphNodeType.Artifact, artifactId));
        graph.AddNode(new GraphNode(keyId, GraphNodeType.Key, keyId));
        graph.AddEdge(new GraphEdge(artifactId, keyId, GraphEdgeType.SignedBy, "signed by"));
        return graph;
    }
}
