namespace Sigil.Graph;

public sealed class TrustGraph
{
    private readonly Dictionary<string, GraphNode> _nodes = new();
    private readonly Dictionary<string, List<GraphEdge>> _outgoing = new();
    private readonly Dictionary<string, List<GraphEdge>> _incoming = new();

    public int NodeCount => _nodes.Count;
    public int EdgeCount => _outgoing.Values.Sum(e => e.Count);

    public void AddNode(GraphNode node)
    {
        ArgumentNullException.ThrowIfNull(node);
        if (!_nodes.TryAdd(node.Id, node))
            throw new InvalidOperationException($"Node '{node.Id}' already exists.");
    }

    public bool TryAddNode(GraphNode node)
    {
        ArgumentNullException.ThrowIfNull(node);
        if (_nodes.ContainsKey(node.Id))
            return false;
        _nodes.Add(node.Id, node);
        return true;
    }

    public GraphNode GetNode(string id)
    {
        if (_nodes.TryGetValue(id, out var node))
            return node;
        throw new KeyNotFoundException($"Node '{id}' not found.");
    }

    public GraphNode? TryGetNode(string id)
    {
        _nodes.TryGetValue(id, out var node);
        return node;
    }

    public void AddEdge(GraphEdge edge)
    {
        ArgumentNullException.ThrowIfNull(edge);
        if (!_nodes.ContainsKey(edge.SourceId))
            throw new InvalidOperationException($"Source node '{edge.SourceId}' not found.");
        if (!_nodes.ContainsKey(edge.TargetId))
            throw new InvalidOperationException($"Target node '{edge.TargetId}' not found.");

        if (!_outgoing.TryGetValue(edge.SourceId, out var outList))
        {
            outList = new List<GraphEdge>();
            _outgoing[edge.SourceId] = outList;
        }
        outList.Add(edge);

        if (!_incoming.TryGetValue(edge.TargetId, out var inList))
        {
            inList = new List<GraphEdge>();
            _incoming[edge.TargetId] = inList;
        }
        inList.Add(edge);
    }

    public IReadOnlyList<GraphEdge> GetOutgoingEdges(string nodeId)
    {
        return _outgoing.TryGetValue(nodeId, out var edges) ? edges : [];
    }

    public IReadOnlyList<GraphEdge> GetIncomingEdges(string nodeId)
    {
        return _incoming.TryGetValue(nodeId, out var edges) ? edges : [];
    }

    public IReadOnlyList<GraphNode> GetNeighbors(string nodeId)
    {
        if (!_outgoing.TryGetValue(nodeId, out var edges))
            return [];
        var neighborIds = new HashSet<string>();
        var result = new List<GraphNode>();
        foreach (var edge in edges)
        {
            if (neighborIds.Add(edge.TargetId))
                result.Add(_nodes[edge.TargetId]);
        }
        return result;
    }

    public IReadOnlyCollection<GraphNode> AllNodes => _nodes.Values;

    public IEnumerable<GraphEdge> AllEdges => _outgoing.Values.SelectMany(e => e);
}
