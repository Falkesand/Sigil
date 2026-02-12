using System.Text.Json;
using System.Text.Json.Serialization;

namespace Sigil.Graph;

public static class GraphSerializer
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public static GraphResult<string> Serialize(TrustGraph graph)
    {
        ArgumentNullException.ThrowIfNull(graph);

        try
        {
            var data = new GraphData();

            foreach (var node in graph.AllNodes)
            {
                data.Nodes.Add(new NodeData
                {
                    Id = node.Id,
                    Type = node.Type.ToString(),
                    Label = node.Label,
                    Properties = node.Properties.Count > 0 ? new Dictionary<string, string>(node.Properties) : null
                });
            }

            foreach (var edge in graph.AllEdges)
            {
                data.Edges.Add(new EdgeData
                {
                    Source = edge.SourceId,
                    Target = edge.TargetId,
                    Type = edge.Type.ToString(),
                    Label = edge.Label,
                    Properties = edge.Properties.Count > 0 ? new Dictionary<string, string>(edge.Properties) : null
                });
            }

            var json = JsonSerializer.Serialize(data, JsonOptions);
            return GraphResult<string>.Ok(json);
        }
        catch (JsonException ex)
        {
            return GraphResult<string>.Fail(GraphErrorKind.SerializationFailed, ex.Message);
        }
    }

    public static GraphResult<TrustGraph> Deserialize(string json)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);

        try
        {
            var data = JsonSerializer.Deserialize<GraphData>(json, JsonOptions);
            if (data is null)
                return GraphResult<TrustGraph>.Fail(GraphErrorKind.DeserializationFailed, "Failed to deserialize graph data.");

            var graph = new TrustGraph();

            foreach (var nodeData in data.Nodes)
            {
                if (!Enum.TryParse<GraphNodeType>(nodeData.Type, out var nodeType))
                    return GraphResult<TrustGraph>.Fail(GraphErrorKind.DeserializationFailed, $"Unknown node type: {nodeData.Type}");

                var node = new GraphNode(nodeData.Id, nodeType, nodeData.Label);
                if (nodeData.Properties is not null)
                {
                    foreach (var (key, value) in nodeData.Properties)
                        node.Properties[key] = value;
                }
                graph.AddNode(node);
            }

            foreach (var edgeData in data.Edges)
            {
                if (!Enum.TryParse<GraphEdgeType>(edgeData.Type, out var edgeType))
                    return GraphResult<TrustGraph>.Fail(GraphErrorKind.DeserializationFailed, $"Unknown edge type: {edgeData.Type}");

                var edge = new GraphEdge(edgeData.Source, edgeData.Target, edgeType, edgeData.Label);
                if (edgeData.Properties is not null)
                {
                    foreach (var (key, value) in edgeData.Properties)
                        edge.Properties[key] = value;
                }
                graph.AddEdge(edge);
            }

            return GraphResult<TrustGraph>.Ok(graph);
        }
        catch (JsonException ex)
        {
            return GraphResult<TrustGraph>.Fail(GraphErrorKind.DeserializationFailed, ex.Message);
        }
    }

    private sealed class GraphData
    {
        [JsonPropertyName("nodes")]
        public List<NodeData> Nodes { get; init; } = [];

        [JsonPropertyName("edges")]
        public List<EdgeData> Edges { get; init; } = [];
    }

    private sealed class NodeData
    {
        [JsonPropertyName("id")]
        public required string Id { get; init; }

        [JsonPropertyName("type")]
        public required string Type { get; init; }

        [JsonPropertyName("label")]
        public required string Label { get; init; }

        [JsonPropertyName("properties")]
        public Dictionary<string, string>? Properties { get; init; }
    }

    private sealed class EdgeData
    {
        [JsonPropertyName("source")]
        public required string Source { get; init; }

        [JsonPropertyName("target")]
        public required string Target { get; init; }

        [JsonPropertyName("type")]
        public required string Type { get; init; }

        [JsonPropertyName("label")]
        public required string Label { get; init; }

        [JsonPropertyName("properties")]
        public Dictionary<string, string>? Properties { get; init; }
    }
}
