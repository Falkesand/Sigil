using System.Text.Json;
using System.Text.Json.Serialization;

namespace Sigil.Graph;

public static class JsonExporter
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public static string Export(TrustGraph graph)
    {
        ArgumentNullException.ThrowIfNull(graph);

        var nodes = new List<JsonNode>();
        foreach (var node in graph.AllNodes)
        {
            nodes.Add(new JsonNode
            {
                Id = node.Id,
                Type = node.Type.ToString(),
                Label = node.Label,
                Properties = node.Properties.Count > 0 ? new Dictionary<string, string>(node.Properties) : null
            });
        }

        var edges = new List<JsonEdge>();
        foreach (var edge in graph.AllEdges)
        {
            edges.Add(new JsonEdge
            {
                Source = edge.SourceId,
                Target = edge.TargetId,
                Type = edge.Type.ToString(),
                Label = edge.Label,
                Properties = edge.Properties.Count > 0 ? new Dictionary<string, string>(edge.Properties) : null
            });
        }

        var graphData = new JsonGraph { Nodes = nodes, Edges = edges };
        return JsonSerializer.Serialize(graphData, JsonOptions);
    }

    private sealed class JsonGraph
    {
        [JsonPropertyName("nodes")]
        public List<JsonNode> Nodes { get; init; } = [];

        [JsonPropertyName("edges")]
        public List<JsonEdge> Edges { get; init; } = [];
    }

    private sealed class JsonNode
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

    private sealed class JsonEdge
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
