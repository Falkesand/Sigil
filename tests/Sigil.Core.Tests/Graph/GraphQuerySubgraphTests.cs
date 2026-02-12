using Sigil.Graph;

namespace Sigil.Core.Tests.Graph;

public class GraphQuerySubgraphTests
{
    [Fact]
    public void Subgraph_extracts_nodes()
    {
        var graph = BuildThreeNodeGraph();

        var sub = GraphQuery.Subgraph(graph, ["A", "B"]);

        Assert.Equal(2, sub.NodeCount);
        Assert.NotNull(sub.TryGetNode("A"));
        Assert.NotNull(sub.TryGetNode("B"));
        Assert.Null(sub.TryGetNode("C"));
    }

    [Fact]
    public void Subgraph_includes_edges_between_selected()
    {
        var graph = BuildThreeNodeGraph();

        var sub = GraphQuery.Subgraph(graph, ["A", "B"]);

        Assert.Equal(1, sub.EdgeCount);
        var edges = sub.GetOutgoingEdges("A");
        Assert.Single(edges);
        Assert.Equal("B", edges[0].TargetId);
    }

    [Fact]
    public void Subgraph_excludes_edges_to_unselected()
    {
        var graph = BuildThreeNodeGraph();

        var sub = GraphQuery.Subgraph(graph, ["A"]);

        Assert.Equal(1, sub.NodeCount);
        Assert.Equal(0, sub.EdgeCount);
    }

    [Fact]
    public void Subgraph_empty_selection()
    {
        var graph = BuildThreeNodeGraph();

        var sub = GraphQuery.Subgraph(graph, Array.Empty<string>());

        Assert.Equal(0, sub.NodeCount);
        Assert.Equal(0, sub.EdgeCount);
    }

    [Fact]
    public void Subgraph_missing_nodes_skipped()
    {
        var graph = BuildThreeNodeGraph();

        var sub = GraphQuery.Subgraph(graph, ["nonexistent1", "nonexistent2"]);

        Assert.Equal(0, sub.NodeCount);
        Assert.Equal(0, sub.EdgeCount);
    }

    [Fact]
    public void Subgraph_preserves_properties()
    {
        var graph = new TrustGraph();
        var node = new GraphNode("A", GraphNodeType.Artifact, "app.dll");
        node.Properties["hash"] = "sha256:abc123";
        graph.AddNode(node);

        var keyNode = new GraphNode("B", GraphNodeType.Key, "Key B");
        keyNode.Properties["algorithm"] = "ecdsa-p256";
        graph.AddNode(keyNode);

        var edge = new GraphEdge("A", "B", GraphEdgeType.SignedBy, "signed by");
        edge.Properties["timestamp"] = "2025-06-15T10:00:00Z";
        graph.AddEdge(edge);

        var sub = GraphQuery.Subgraph(graph, ["A", "B"]);

        var subNode = sub.GetNode("A");
        Assert.Equal("sha256:abc123", subNode.Properties["hash"]);

        var subKey = sub.GetNode("B");
        Assert.Equal("ecdsa-p256", subKey.Properties["algorithm"]);

        var subEdges = sub.GetOutgoingEdges("A");
        Assert.Single(subEdges);
        Assert.Equal("2025-06-15T10:00:00Z", subEdges[0].Properties["timestamp"]);
    }

    /// <summary>
    /// Builds a graph: A --(SignedBy)--> B --(EndorsedBy)--> C
    /// </summary>
    private static TrustGraph BuildThreeNodeGraph()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("A", GraphNodeType.Artifact, "A"));
        graph.AddNode(new GraphNode("B", GraphNodeType.Key, "B"));
        graph.AddNode(new GraphNode("C", GraphNodeType.Key, "C"));
        graph.AddEdge(new GraphEdge("A", "B", GraphEdgeType.SignedBy, "A->B"));
        graph.AddEdge(new GraphEdge("B", "C", GraphEdgeType.EndorsedBy, "B->C"));
        return graph;
    }
}
