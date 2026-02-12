using Sigil.Graph;

namespace Sigil.Core.Tests.Graph;

public class GraphSerializerTests
{
    [Fact]
    public void Serialize_round_trip_preserves_node_and_edge_counts()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("artifact:app.exe", GraphNodeType.Artifact, "app.exe"));
        graph.AddNode(new GraphNode("key:sha256:k1", GraphNodeType.Key, "k1"));
        graph.AddEdge(new GraphEdge("artifact:app.exe", "key:sha256:k1", GraphEdgeType.SignedBy, "signed by"));

        var serializeResult = GraphSerializer.Serialize(graph);
        Assert.True(serializeResult.IsSuccess);

        var deserializeResult = GraphSerializer.Deserialize(serializeResult.Value);
        Assert.True(deserializeResult.IsSuccess);

        var restored = deserializeResult.Value;
        Assert.Equal(graph.NodeCount, restored.NodeCount);
        Assert.Equal(graph.EdgeCount, restored.EdgeCount);
    }

    [Fact]
    public void Serialize_preserves_node_properties()
    {
        var graph = new TrustGraph();
        var node = new GraphNode("key:sha256:k1", GraphNodeType.Key, "k1");
        node.Properties["algorithm"] = "ecdsa-p256";
        node.Properties["fingerprint"] = "sha256:k1";
        graph.AddNode(node);

        var serializeResult = GraphSerializer.Serialize(graph);
        Assert.True(serializeResult.IsSuccess);

        var deserializeResult = GraphSerializer.Deserialize(serializeResult.Value);
        Assert.True(deserializeResult.IsSuccess);

        var restored = deserializeResult.Value;
        var restoredNode = restored.GetNode("key:sha256:k1");
        Assert.Equal("ecdsa-p256", restoredNode.Properties["algorithm"]);
        Assert.Equal("sha256:k1", restoredNode.Properties["fingerprint"]);
    }

    [Fact]
    public void Serialize_preserves_edge_properties()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("key:sha256:rev", GraphNodeType.Key, "rev"));
        var edge = new GraphEdge("key:sha256:rev", "key:sha256:rev", GraphEdgeType.RevokedAt, "revoked");
        edge.Properties["revokedAt"] = "2026-01-15T00:00:00Z";
        edge.Properties["reason"] = "compromised";
        graph.AddEdge(edge);

        var serializeResult = GraphSerializer.Serialize(graph);
        Assert.True(serializeResult.IsSuccess);

        var deserializeResult = GraphSerializer.Deserialize(serializeResult.Value);
        Assert.True(deserializeResult.IsSuccess);

        var restored = deserializeResult.Value;
        var edges = restored.GetOutgoingEdges("key:sha256:rev");
        Assert.Single(edges);
        Assert.Equal("2026-01-15T00:00:00Z", edges[0].Properties["revokedAt"]);
        Assert.Equal("compromised", edges[0].Properties["reason"]);
    }

    [Fact]
    public void Deserialize_invalid_json_fails()
    {
        var result = GraphSerializer.Deserialize("{ not valid json at all }}}");

        Assert.False(result.IsSuccess);
        Assert.Equal(GraphErrorKind.DeserializationFailed, result.ErrorKind);
    }

    [Fact]
    public void Deserialize_unknown_node_type_fails()
    {
        var json = """
        {
          "nodes": [
            { "id": "x", "type": "UnknownType", "label": "x" }
          ],
          "edges": []
        }
        """;

        var result = GraphSerializer.Deserialize(json);

        Assert.False(result.IsSuccess);
        Assert.Equal(GraphErrorKind.DeserializationFailed, result.ErrorKind);
        Assert.Contains("UnknownType", result.ErrorMessage);
    }

    [Fact]
    public void Deserialize_empty_string_throws_argument_exception()
    {
        Assert.Throws<ArgumentException>(() => GraphSerializer.Deserialize(""));
        Assert.Throws<ArgumentException>(() => GraphSerializer.Deserialize("   "));
    }
}
