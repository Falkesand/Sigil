namespace Sigil.Graph;

public sealed class GraphNode
{
    public string Id { get; }
    public GraphNodeType Type { get; }
    public string Label { get; }
    public Dictionary<string, string> Properties { get; } = new();

    public GraphNode(string id, GraphNodeType type, string label)
    {
        Id = id ?? throw new ArgumentNullException(nameof(id));
        Type = type;
        Label = label ?? throw new ArgumentNullException(nameof(label));
    }
}
