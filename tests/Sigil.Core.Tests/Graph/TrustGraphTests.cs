using Sigil.Graph;

namespace Sigil.Core.Tests.Graph;

public class TrustGraphTests
{
    [Fact]
    public void Empty_graph_has_zero_counts()
    {
        var graph = new TrustGraph();

        Assert.Equal(0, graph.NodeCount);
        Assert.Equal(0, graph.EdgeCount);
    }

    [Fact]
    public void AddNode_increments_count()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("key1", GraphNodeType.Key, "Key 1"));

        Assert.Equal(1, graph.NodeCount);
    }

    [Fact]
    public void AddNode_duplicate_throws()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("key1", GraphNodeType.Key, "Key 1"));

        Assert.Throws<InvalidOperationException>(() =>
            graph.AddNode(new GraphNode("key1", GraphNodeType.Key, "Key 1 Dup")));
    }

    [Fact]
    public void TryAddNode_returns_true_for_new_node()
    {
        var graph = new TrustGraph();

        var added = graph.TryAddNode(new GraphNode("key1", GraphNodeType.Key, "Key 1"));

        Assert.True(added);
        Assert.Equal(1, graph.NodeCount);
    }

    [Fact]
    public void TryAddNode_returns_false_for_duplicate()
    {
        var graph = new TrustGraph();
        graph.TryAddNode(new GraphNode("key1", GraphNodeType.Key, "Key 1"));

        var added = graph.TryAddNode(new GraphNode("key1", GraphNodeType.Key, "Key 1 Dup"));

        Assert.False(added);
        Assert.Equal(1, graph.NodeCount);
    }

    [Fact]
    public void GetNode_returns_added_node()
    {
        var graph = new TrustGraph();
        var node = new GraphNode("artifact1", GraphNodeType.Artifact, "build.zip");
        graph.AddNode(node);

        var retrieved = graph.GetNode("artifact1");

        Assert.Same(node, retrieved);
        Assert.Equal("artifact1", retrieved.Id);
        Assert.Equal(GraphNodeType.Artifact, retrieved.Type);
        Assert.Equal("build.zip", retrieved.Label);
    }

    [Fact]
    public void GetNode_missing_throws()
    {
        var graph = new TrustGraph();

        Assert.Throws<KeyNotFoundException>(() => graph.GetNode("nonexistent"));
    }

    [Fact]
    public void TryGetNode_returns_node_when_exists()
    {
        var graph = new TrustGraph();
        var node = new GraphNode("id1", GraphNodeType.Identity, "alice@example.com");
        graph.AddNode(node);

        var found = graph.TryGetNode("id1");

        Assert.NotNull(found);
        Assert.Same(node, found);
    }

    [Fact]
    public void TryGetNode_returns_null_when_missing()
    {
        var graph = new TrustGraph();

        var found = graph.TryGetNode("ghost");

        Assert.Null(found);
    }

    [Fact]
    public void AddEdge_links_nodes()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("artifact", GraphNodeType.Artifact, "app.exe"));
        graph.AddNode(new GraphNode("key", GraphNodeType.Key, "signing-key"));

        graph.AddEdge(new GraphEdge("artifact", "key", GraphEdgeType.SignedBy, "signed"));

        Assert.Equal(1, graph.EdgeCount);
    }

    [Fact]
    public void AddEdge_missing_source_throws()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("target", GraphNodeType.Key, "key"));

        Assert.Throws<InvalidOperationException>(() =>
            graph.AddEdge(new GraphEdge("missing", "target", GraphEdgeType.SignedBy, "bad")));
    }

    [Fact]
    public void AddEdge_missing_target_throws()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("source", GraphNodeType.Artifact, "app.exe"));

        Assert.Throws<InvalidOperationException>(() =>
            graph.AddEdge(new GraphEdge("source", "missing", GraphEdgeType.SignedBy, "bad")));
    }

    [Fact]
    public void GetOutgoingEdges_returns_edges()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("A", GraphNodeType.Artifact, "a"));
        graph.AddNode(new GraphNode("B", GraphNodeType.Key, "b"));
        graph.AddEdge(new GraphEdge("A", "B", GraphEdgeType.SignedBy, "sig"));

        var edges = graph.GetOutgoingEdges("A");

        Assert.Single(edges);
        Assert.Equal("A", edges[0].SourceId);
        Assert.Equal("B", edges[0].TargetId);
    }

    [Fact]
    public void GetOutgoingEdges_empty_for_no_edges()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("lonely", GraphNodeType.Key, "lonely-key"));

        var edges = graph.GetOutgoingEdges("lonely");

        Assert.Empty(edges);
    }

    [Fact]
    public void GetIncomingEdges_returns_edges()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("A", GraphNodeType.Artifact, "a"));
        graph.AddNode(new GraphNode("B", GraphNodeType.Key, "b"));
        graph.AddEdge(new GraphEdge("A", "B", GraphEdgeType.SignedBy, "sig"));

        var edges = graph.GetIncomingEdges("B");

        Assert.Single(edges);
        Assert.Equal("A", edges[0].SourceId);
        Assert.Equal("B", edges[0].TargetId);
    }

    [Fact]
    public void GetIncomingEdges_empty_for_no_edges()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("isolated", GraphNodeType.Identity, "nobody"));

        var edges = graph.GetIncomingEdges("isolated");

        Assert.Empty(edges);
    }

    [Fact]
    public void GetNeighbors_returns_target_nodes()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("A", GraphNodeType.Artifact, "a"));
        graph.AddNode(new GraphNode("B", GraphNodeType.Key, "b"));
        graph.AddNode(new GraphNode("C", GraphNodeType.Identity, "c"));
        graph.AddEdge(new GraphEdge("A", "B", GraphEdgeType.SignedBy, "sig1"));
        graph.AddEdge(new GraphEdge("A", "C", GraphEdgeType.AttestedBy, "att1"));

        var neighbors = graph.GetNeighbors("A");

        Assert.Equal(2, neighbors.Count);
        var ids = neighbors.Select(n => n.Id).OrderBy(id => id).ToList();
        Assert.Equal("B", ids[0]);
        Assert.Equal("C", ids[1]);
    }

    [Fact]
    public void GetNeighbors_deduplicates()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("A", GraphNodeType.Artifact, "a"));
        graph.AddNode(new GraphNode("B", GraphNodeType.Key, "b"));
        graph.AddEdge(new GraphEdge("A", "B", GraphEdgeType.SignedBy, "sig1"));
        graph.AddEdge(new GraphEdge("A", "B", GraphEdgeType.EndorsedBy, "end1"));

        var neighbors = graph.GetNeighbors("A");

        Assert.Single(neighbors);
        Assert.Equal("B", neighbors[0].Id);
    }

    [Fact]
    public void AllNodes_returns_all_nodes()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("n1", GraphNodeType.Key, "key1"));
        graph.AddNode(new GraphNode("n2", GraphNodeType.Artifact, "art1"));
        graph.AddNode(new GraphNode("n3", GraphNodeType.Identity, "id1"));

        Assert.Equal(3, graph.AllNodes.Count);
    }

    [Fact]
    public void AllEdges_returns_all_edges()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("A", GraphNodeType.Artifact, "a"));
        graph.AddNode(new GraphNode("B", GraphNodeType.Key, "b"));
        graph.AddNode(new GraphNode("C", GraphNodeType.Identity, "c"));
        graph.AddEdge(new GraphEdge("A", "B", GraphEdgeType.SignedBy, "sig"));
        graph.AddEdge(new GraphEdge("A", "C", GraphEdgeType.AttestedBy, "att"));
        graph.AddEdge(new GraphEdge("B", "C", GraphEdgeType.IdentityBoundTo, "bind"));

        var allEdges = graph.AllEdges.ToList();

        Assert.Equal(3, allEdges.Count);
    }

    [Fact]
    public void Node_properties_are_mutable()
    {
        var graph = new TrustGraph();
        var node = new GraphNode("key1", GraphNodeType.Key, "signing-key");
        graph.AddNode(node);

        node.Properties["algorithm"] = "ecdsa-p256";
        node.Properties["fingerprint"] = "sha256:abc123";

        var retrieved = graph.GetNode("key1");
        Assert.Equal("ecdsa-p256", retrieved.Properties["algorithm"]);
        Assert.Equal("sha256:abc123", retrieved.Properties["fingerprint"]);
    }

    [Fact]
    public void Edge_properties_are_mutable()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("A", GraphNodeType.Artifact, "a"));
        graph.AddNode(new GraphNode("B", GraphNodeType.Key, "b"));
        var edge = new GraphEdge("A", "B", GraphEdgeType.SignedBy, "signature");
        graph.AddEdge(edge);

        edge.Properties["timestamp"] = "2025-01-15T12:00:00Z";
        edge.Properties["algorithm"] = "ecdsa-p256";

        var edges = graph.GetOutgoingEdges("A");
        Assert.Equal("2025-01-15T12:00:00Z", edges[0].Properties["timestamp"]);
        Assert.Equal("ecdsa-p256", edges[0].Properties["algorithm"]);
    }
}
