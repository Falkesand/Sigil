using Sigil.Graph;

namespace Sigil.Core.Tests.Graph;

public class GraphQueryReachableTests
{
    [Fact]
    public void Reachable_from_artifact_finds_key()
    {
        var graph = BuildSimpleGraph();

        var result = GraphQuery.Reachable(graph, "artifact:app.dll");

        Assert.True(result.IsSuccess);
        Assert.Contains("key:sha256:aaa", result.Value);
        Assert.Single(result.Value);
    }

    [Fact]
    public void Reachable_follows_chain()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("artifact:app.dll", GraphNodeType.Artifact, "app.dll"));
        graph.AddNode(new GraphNode("key:sha256:k1", GraphNodeType.Key, "Key 1"));
        graph.AddNode(new GraphNode("key:sha256:k2", GraphNodeType.Key, "Key 2"));
        graph.AddEdge(new GraphEdge("artifact:app.dll", "key:sha256:k1", GraphEdgeType.SignedBy, "signed by K1"));
        graph.AddEdge(new GraphEdge("key:sha256:k1", "key:sha256:k2", GraphEdgeType.EndorsedBy, "endorsed by K2"));

        var result = GraphQuery.Reachable(graph, "artifact:app.dll");

        Assert.True(result.IsSuccess);
        Assert.Contains("key:sha256:k1", result.Value);
        Assert.Contains("key:sha256:k2", result.Value);
        Assert.Equal(2, result.Value.Count);
    }

    [Fact]
    public void Reachable_handles_cycle()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("A", GraphNodeType.Artifact, "A"));
        graph.AddNode(new GraphNode("B", GraphNodeType.Key, "B"));
        graph.AddNode(new GraphNode("C", GraphNodeType.Key, "C"));
        graph.AddEdge(new GraphEdge("A", "B", GraphEdgeType.SignedBy, "A->B"));
        graph.AddEdge(new GraphEdge("B", "C", GraphEdgeType.EndorsedBy, "B->C"));
        graph.AddEdge(new GraphEdge("C", "A", GraphEdgeType.EndorsedBy, "C->A"));

        var result = GraphQuery.Reachable(graph, "A");

        Assert.True(result.IsSuccess);
        Assert.Contains("B", result.Value);
        Assert.Contains("C", result.Value);
        Assert.DoesNotContain("A", result.Value);
    }

    [Fact]
    public void Reachable_returns_empty_for_isolated_node()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("lonely", GraphNodeType.Key, "Lonely Key"));

        var result = GraphQuery.Reachable(graph, "lonely");

        Assert.True(result.IsSuccess);
        Assert.Empty(result.Value);
    }

    [Fact]
    public void Reachable_node_not_found_returns_error()
    {
        var graph = new TrustGraph();

        var result = GraphQuery.Reachable(graph, "nonexistent");

        Assert.False(result.IsSuccess);
        Assert.Equal(GraphErrorKind.NodeNotFound, result.ErrorKind);
    }

    [Fact]
    public void Reachable_excludes_start_node()
    {
        var graph = BuildSimpleGraph();

        var result = GraphQuery.Reachable(graph, "artifact:app.dll");

        Assert.True(result.IsSuccess);
        Assert.DoesNotContain("artifact:app.dll", result.Value);
    }

    [Fact]
    public void Reachable_follows_multiple_outgoing()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("A", GraphNodeType.Artifact, "A"));
        graph.AddNode(new GraphNode("B", GraphNodeType.Key, "B"));
        graph.AddNode(new GraphNode("C", GraphNodeType.Key, "C"));
        graph.AddEdge(new GraphEdge("A", "B", GraphEdgeType.SignedBy, "A->B"));
        graph.AddEdge(new GraphEdge("A", "C", GraphEdgeType.SignedBy, "A->C"));

        var result = GraphQuery.Reachable(graph, "A");

        Assert.True(result.IsSuccess);
        Assert.Contains("B", result.Value);
        Assert.Contains("C", result.Value);
        Assert.Equal(2, result.Value.Count);
    }

    [Fact]
    public void Reachable_transitive()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("A", GraphNodeType.Artifact, "A"));
        graph.AddNode(new GraphNode("B", GraphNodeType.Key, "B"));
        graph.AddNode(new GraphNode("C", GraphNodeType.Key, "C"));
        graph.AddEdge(new GraphEdge("A", "B", GraphEdgeType.SignedBy, "A->B"));
        graph.AddEdge(new GraphEdge("B", "C", GraphEdgeType.EndorsedBy, "B->C"));

        var result = GraphQuery.Reachable(graph, "A");

        Assert.True(result.IsSuccess);
        Assert.Contains("B", result.Value);
        Assert.Contains("C", result.Value);
        Assert.Equal(2, result.Value.Count);
    }

    private static TrustGraph BuildSimpleGraph()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("artifact:app.dll", GraphNodeType.Artifact, "app.dll"));
        graph.AddNode(new GraphNode("key:sha256:aaa", GraphNodeType.Key, "Key A"));
        graph.AddEdge(new GraphEdge("artifact:app.dll", "key:sha256:aaa", GraphEdgeType.SignedBy, "signed by"));
        return graph;
    }
}
