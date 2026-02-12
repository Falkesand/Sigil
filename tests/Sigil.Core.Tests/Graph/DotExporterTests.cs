using Sigil.Graph;

namespace Sigil.Core.Tests.Graph;

public class DotExporterTests
{
    [Fact]
    public void Export_empty_graph_returns_valid_dot_with_no_nodes_or_edges()
    {
        var graph = new TrustGraph();

        var dot = DotExporter.Export(graph);

        Assert.Contains("digraph TrustGraph {", dot);
        Assert.Contains("rankdir=LR;", dot);
        Assert.EndsWith("}" + Environment.NewLine, dot);
    }

    [Fact]
    public void Export_single_node_contains_node_with_correct_label()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("artifact:app.dll", GraphNodeType.Artifact, "app.dll"));

        var dot = DotExporter.Export(graph);

        Assert.Contains("\"artifact:app.dll\"", dot);
        Assert.Contains("label=\"app.dll\"", dot);
    }

    [Fact]
    public void Export_key_node_has_hexagon_shape()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("key:sha256:abc", GraphNodeType.Key, "signing-key"));

        var dot = DotExporter.Export(graph);

        Assert.Contains("shape=hexagon", dot);
    }

    [Fact]
    public void Export_artifact_node_has_box_shape()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("artifact:lib.dll", GraphNodeType.Artifact, "lib.dll"));

        var dot = DotExporter.Export(graph);

        Assert.Contains("shape=box", dot);
    }

    [Fact]
    public void Export_edge_appears_in_output_with_label()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("artifact:app.exe", GraphNodeType.Artifact, "app.exe"));
        graph.AddNode(new GraphNode("key:sha256:k1", GraphNodeType.Key, "k1"));
        graph.AddEdge(new GraphEdge("artifact:app.exe", "key:sha256:k1", GraphEdgeType.SignedBy, "signed by"));

        var dot = DotExporter.Export(graph);

        Assert.Contains("\"artifact:app.exe\" -> \"key:sha256:k1\"", dot);
        Assert.Contains("label=\"signed by\"", dot);
    }

    [Fact]
    public void Export_revoked_edge_has_red_color()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("key:sha256:revoked", GraphNodeType.Key, "revoked-key"));
        graph.AddEdge(new GraphEdge("key:sha256:revoked", "key:sha256:revoked", GraphEdgeType.RevokedAt, "revoked"));

        var dot = DotExporter.Export(graph);

        Assert.Contains("color=red", dot);
        Assert.Contains("fontcolor=red", dot);
    }

    [Fact]
    public void Export_escapes_special_characters_in_label()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("node:1", GraphNodeType.Artifact, "path\\to\\file \"quoted\""));

        var dot = DotExporter.Export(graph);

        Assert.Contains("label=\"path\\\\to\\\\file \\\"quoted\\\"\"", dot);
    }
}
