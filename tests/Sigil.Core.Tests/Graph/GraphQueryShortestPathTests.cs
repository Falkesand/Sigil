using Sigil.Graph;

namespace Sigil.Core.Tests.Graph;

public class GraphQueryShortestPathTests
{
    [Fact]
    public void ShortestPath_direct()
    {
        var graph = BuildLinearGraph("A", "B");

        var result = GraphQuery.ShortestPath(graph, "A", "B");

        Assert.True(result.IsSuccess);
        Assert.Equal(["A", "B"], result.Value);
    }

    [Fact]
    public void ShortestPath_multi_hop()
    {
        var graph = BuildLinearGraph("A", "B", "C");

        var result = GraphQuery.ShortestPath(graph, "A", "C");

        Assert.True(result.IsSuccess);
        Assert.Equal(["A", "B", "C"], result.Value);
    }

    [Fact]
    public void ShortestPath_same_node()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("A", GraphNodeType.Artifact, "A"));

        var result = GraphQuery.ShortestPath(graph, "A", "A");

        Assert.True(result.IsSuccess);
        Assert.Empty(result.Value);
    }

    [Fact]
    public void ShortestPath_no_path()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("A", GraphNodeType.Artifact, "A"));
        graph.AddNode(new GraphNode("B", GraphNodeType.Key, "B"));

        var result = GraphQuery.ShortestPath(graph, "A", "B");

        Assert.True(result.IsSuccess);
        Assert.Empty(result.Value);
    }

    [Fact]
    public void ShortestPath_from_not_found()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("B", GraphNodeType.Key, "B"));

        var result = GraphQuery.ShortestPath(graph, "missing", "B");

        Assert.False(result.IsSuccess);
        Assert.Equal(GraphErrorKind.NodeNotFound, result.ErrorKind);
    }

    [Fact]
    public void ShortestPath_to_not_found()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("A", GraphNodeType.Artifact, "A"));

        var result = GraphQuery.ShortestPath(graph, "A", "missing");

        Assert.False(result.IsSuccess);
        Assert.Equal(GraphErrorKind.NodeNotFound, result.ErrorKind);
    }

    [Fact]
    public void ShortestPath_chooses_shorter()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("A", GraphNodeType.Artifact, "A"));
        graph.AddNode(new GraphNode("B", GraphNodeType.Key, "B"));
        graph.AddNode(new GraphNode("C", GraphNodeType.Key, "C"));
        graph.AddNode(new GraphNode("D", GraphNodeType.Key, "D"));
        // Short path: A -> B -> D
        graph.AddEdge(new GraphEdge("A", "B", GraphEdgeType.SignedBy, "A->B"));
        graph.AddEdge(new GraphEdge("B", "D", GraphEdgeType.EndorsedBy, "B->D"));
        // Long path: A -> C -> B -> D
        graph.AddEdge(new GraphEdge("A", "C", GraphEdgeType.SignedBy, "A->C"));
        graph.AddEdge(new GraphEdge("C", "B", GraphEdgeType.EndorsedBy, "C->B"));

        var result = GraphQuery.ShortestPath(graph, "A", "D");

        Assert.True(result.IsSuccess);
        Assert.Equal(["A", "B", "D"], result.Value);
    }

    [Fact]
    public void ShortestPath_handles_cycle()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("A", GraphNodeType.Artifact, "A"));
        graph.AddNode(new GraphNode("B", GraphNodeType.Key, "B"));
        graph.AddNode(new GraphNode("C", GraphNodeType.Key, "C"));
        graph.AddEdge(new GraphEdge("A", "B", GraphEdgeType.SignedBy, "A->B"));
        graph.AddEdge(new GraphEdge("B", "C", GraphEdgeType.EndorsedBy, "B->C"));
        graph.AddEdge(new GraphEdge("C", "A", GraphEdgeType.EndorsedBy, "C->A"));

        var result = GraphQuery.ShortestPath(graph, "A", "C");

        Assert.True(result.IsSuccess);
        Assert.Equal(["A", "B", "C"], result.Value);
    }

    /// <summary>
    /// Builds a linear graph: n0 -> n1 -> n2 -> ... with SignedBy edges.
    /// All nodes are Key type except the first which is Artifact.
    /// </summary>
    private static TrustGraph BuildLinearGraph(params string[] nodeIds)
    {
        var graph = new TrustGraph();

        for (var i = 0; i < nodeIds.Length; i++)
        {
            var type = i == 0 ? GraphNodeType.Artifact : GraphNodeType.Key;
            graph.AddNode(new GraphNode(nodeIds[i], type, nodeIds[i]));
        }

        for (var i = 0; i < nodeIds.Length - 1; i++)
        {
            graph.AddEdge(new GraphEdge(nodeIds[i], nodeIds[i + 1], GraphEdgeType.SignedBy, $"{nodeIds[i]}->{nodeIds[i + 1]}"));
        }

        return graph;
    }
}
