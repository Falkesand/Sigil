using System.Text.Json;
using Sigil.Graph;

namespace Sigil.Core.Tests.Graph;

public class JsonExporterTests
{
    [Fact]
    public void Export_empty_graph_returns_valid_json_with_empty_arrays()
    {
        var graph = new TrustGraph();

        var json = JsonExporter.Export(graph);

        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        Assert.Equal(0, root.GetProperty("nodes").GetArrayLength());
        Assert.Equal(0, root.GetProperty("edges").GetArrayLength());
    }

    [Fact]
    public void Export_node_appears_with_id_type_and_label()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("key:sha256:abc", GraphNodeType.Key, "my-key"));

        var json = JsonExporter.Export(graph);

        using var doc = JsonDocument.Parse(json);
        var nodes = doc.RootElement.GetProperty("nodes");
        Assert.Equal(1, nodes.GetArrayLength());
        var node = nodes[0];
        Assert.Equal("key:sha256:abc", node.GetProperty("id").GetString());
        Assert.Equal("Key", node.GetProperty("type").GetString());
        Assert.Equal("my-key", node.GetProperty("label").GetString());
    }

    [Fact]
    public void Export_edge_appears_with_source_target_and_type()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("artifact:app.exe", GraphNodeType.Artifact, "app.exe"));
        graph.AddNode(new GraphNode("key:sha256:k1", GraphNodeType.Key, "k1"));
        graph.AddEdge(new GraphEdge("artifact:app.exe", "key:sha256:k1", GraphEdgeType.SignedBy, "signed by"));

        var json = JsonExporter.Export(graph);

        using var doc = JsonDocument.Parse(json);
        var edges = doc.RootElement.GetProperty("edges");
        Assert.Equal(1, edges.GetArrayLength());
        var edge = edges[0];
        Assert.Equal("artifact:app.exe", edge.GetProperty("source").GetString());
        Assert.Equal("key:sha256:k1", edge.GetProperty("target").GetString());
        Assert.Equal("SignedBy", edge.GetProperty("type").GetString());
        Assert.Equal("signed by", edge.GetProperty("label").GetString());
    }

    [Fact]
    public void Export_properties_included_when_non_empty()
    {
        var graph = new TrustGraph();
        var node = new GraphNode("key:sha256:k1", GraphNodeType.Key, "k1");
        node.Properties["algorithm"] = "ecdsa-p256";
        graph.AddNode(node);

        var json = JsonExporter.Export(graph);

        using var doc = JsonDocument.Parse(json);
        var nodeEl = doc.RootElement.GetProperty("nodes")[0];
        Assert.True(nodeEl.TryGetProperty("properties", out var props));
        Assert.Equal("ecdsa-p256", props.GetProperty("algorithm").GetString());
    }

    [Fact]
    public void Export_properties_excluded_when_empty()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("key:sha256:k1", GraphNodeType.Key, "k1"));

        var json = JsonExporter.Export(graph);

        using var doc = JsonDocument.Parse(json);
        var nodeEl = doc.RootElement.GetProperty("nodes")[0];
        Assert.False(nodeEl.TryGetProperty("properties", out _));
    }
}
