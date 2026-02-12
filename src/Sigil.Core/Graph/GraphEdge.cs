namespace Sigil.Graph;

public sealed class GraphEdge
{
    public string SourceId { get; }
    public string TargetId { get; }
    public GraphEdgeType Type { get; }
    public string Label { get; }
    public Dictionary<string, string> Properties { get; } = new();

    public GraphEdge(string sourceId, string targetId, GraphEdgeType type, string label)
    {
        SourceId = sourceId ?? throw new ArgumentNullException(nameof(sourceId));
        TargetId = targetId ?? throw new ArgumentNullException(nameof(targetId));
        Type = type;
        Label = label ?? throw new ArgumentNullException(nameof(label));
    }
}
