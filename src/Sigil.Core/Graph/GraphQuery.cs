namespace Sigil.Graph;

public static class GraphQuery
{
    /// <summary>
    /// BFS all reachable nodes via outgoing edges starting from <paramref name="nodeId"/>.
    /// The start node itself is excluded from the result.
    /// </summary>
    public static GraphResult<IReadOnlySet<string>> Reachable(TrustGraph graph, string nodeId)
    {
        ArgumentNullException.ThrowIfNull(graph);
        ArgumentNullException.ThrowIfNull(nodeId);

        if (graph.TryGetNode(nodeId) is null)
            return GraphResult<IReadOnlySet<string>>.Fail(GraphErrorKind.NodeNotFound, $"Node '{nodeId}' not found.");

        var visited = new HashSet<string>();
        var queue = new Queue<string>();
        queue.Enqueue(nodeId);

        while (queue.Count > 0)
        {
            var current = queue.Dequeue();
            foreach (var edge in graph.GetOutgoingEdges(current))
            {
                if (visited.Add(edge.TargetId))
                    queue.Enqueue(edge.TargetId);
            }
        }

        // Remove start node — it may have been added if there's a cycle back to it
        visited.Remove(nodeId);

        return GraphResult<IReadOnlySet<string>>.Ok(visited);
    }

    /// <summary>
    /// BFS shortest path from <paramref name="fromId"/> to <paramref name="toId"/>.
    /// Returns an empty list when the target is not reachable or when fromId == toId.
    /// </summary>
    public static GraphResult<IReadOnlyList<string>> ShortestPath(TrustGraph graph, string fromId, string toId)
    {
        ArgumentNullException.ThrowIfNull(graph);
        ArgumentNullException.ThrowIfNull(fromId);
        ArgumentNullException.ThrowIfNull(toId);

        if (graph.TryGetNode(fromId) is null)
            return GraphResult<IReadOnlyList<string>>.Fail(GraphErrorKind.NodeNotFound, $"Node '{fromId}' not found.");

        if (graph.TryGetNode(toId) is null)
            return GraphResult<IReadOnlyList<string>>.Fail(GraphErrorKind.NodeNotFound, $"Node '{toId}' not found.");

        if (fromId == toId)
            return GraphResult<IReadOnlyList<string>>.Ok(Array.Empty<string>());

        var parent = new Dictionary<string, string>();
        var visited = new HashSet<string> { fromId };
        var queue = new Queue<string>();
        queue.Enqueue(fromId);

        while (queue.Count > 0)
        {
            var current = queue.Dequeue();
            foreach (var edge in graph.GetOutgoingEdges(current))
            {
                if (!visited.Add(edge.TargetId))
                    continue;

                parent[edge.TargetId] = current;

                if (edge.TargetId == toId)
                    return GraphResult<IReadOnlyList<string>>.Ok(ReconstructPath(parent, fromId, toId));

                queue.Enqueue(edge.TargetId);
            }
        }

        return GraphResult<IReadOnlyList<string>>.Ok(Array.Empty<string>());
    }

    /// <summary>
    /// Follow SignedBy and EndorsedBy edges from <paramref name="artifactId"/> to root authorities.
    /// Returns all nodes in the chain, including the artifact itself.
    /// </summary>
    public static GraphResult<IReadOnlyList<string>> TrustChain(TrustGraph graph, string artifactId)
    {
        ArgumentNullException.ThrowIfNull(graph);
        ArgumentNullException.ThrowIfNull(artifactId);

        if (graph.TryGetNode(artifactId) is null)
            return GraphResult<IReadOnlyList<string>>.Fail(GraphErrorKind.NodeNotFound, $"Node '{artifactId}' not found.");

        var visited = new HashSet<string>();
        var chain = new List<string>();
        var queue = new Queue<string>();
        queue.Enqueue(artifactId);
        visited.Add(artifactId);

        while (queue.Count > 0)
        {
            var current = queue.Dequeue();
            chain.Add(current);

            foreach (var edge in graph.GetOutgoingEdges(current))
            {
                if (edge.Type is not (GraphEdgeType.SignedBy or GraphEdgeType.EndorsedBy))
                    continue;

                if (visited.Add(edge.TargetId))
                    queue.Enqueue(edge.TargetId);
            }
        }

        return GraphResult<IReadOnlyList<string>>.Ok(chain);
    }

    /// <summary>
    /// Find all artifact/attestation nodes that have a SignedBy edge pointing to <paramref name="keyId"/>.
    /// </summary>
    public static GraphResult<IReadOnlyList<string>> SignedBy(TrustGraph graph, string keyId)
    {
        ArgumentNullException.ThrowIfNull(graph);
        ArgumentNullException.ThrowIfNull(keyId);

        if (graph.TryGetNode(keyId) is null)
            return GraphResult<IReadOnlyList<string>>.Fail(GraphErrorKind.NodeNotFound, $"Node '{keyId}' not found.");

        var result = new List<string>();
        foreach (var edge in graph.GetIncomingEdges(keyId))
        {
            if (edge.Type == GraphEdgeType.SignedBy)
                result.Add(edge.SourceId);
        }

        return GraphResult<IReadOnlyList<string>>.Ok(result);
    }

    /// <summary>
    /// Find all artifact nodes affected by key revocations.
    /// Transitively follows endorsement chains: if key K is revoked and K endorsed key L
    /// (edge L → K with EndorsedBy), then artifacts signed by L are also affected.
    /// </summary>
    public static IReadOnlyList<string> RevokedImpact(TrustGraph graph)
    {
        ArgumentNullException.ThrowIfNull(graph);

        // Step 1: Find all revoked keys (SourceId of RevokedAt edges)
        var revokedKeys = new HashSet<string>();
        foreach (var edge in graph.AllEdges)
        {
            if (edge.Type == GraphEdgeType.RevokedAt)
                revokedKeys.Add(edge.SourceId);
        }

        if (revokedKeys.Count == 0)
            return [];

        // Step 2: BFS from revoked keys via incoming EndorsedBy edges to find transitively affected keys.
        // If K is revoked and L has an EndorsedBy edge to K (L → K), then L depended on K.
        // Incoming EndorsedBy edges of K have SourceId = endorsed key, TargetId = K.
        var affectedKeys = new HashSet<string>(revokedKeys);
        var queue = new Queue<string>(revokedKeys);

        while (queue.Count > 0)
        {
            var current = queue.Dequeue();
            foreach (var edge in graph.GetIncomingEdges(current))
            {
                if (edge.Type == GraphEdgeType.EndorsedBy && affectedKeys.Add(edge.SourceId))
                    queue.Enqueue(edge.SourceId);
            }
        }

        // Step 3: For all affected keys, find artifacts signed by them
        var affectedArtifacts = new HashSet<string>();
        foreach (var keyId in affectedKeys)
        {
            foreach (var edge in graph.GetIncomingEdges(keyId))
            {
                if (edge.Type == GraphEdgeType.SignedBy)
                    affectedArtifacts.Add(edge.SourceId);
            }
        }

        return affectedArtifacts.ToList();
    }

    /// <summary>
    /// Create a new <see cref="TrustGraph"/> containing only the specified nodes and edges between them.
    /// Missing node IDs are silently skipped.
    /// </summary>
    public static TrustGraph Subgraph(TrustGraph graph, IEnumerable<string> nodeIds)
    {
        ArgumentNullException.ThrowIfNull(graph);
        ArgumentNullException.ThrowIfNull(nodeIds);

        var subgraph = new TrustGraph();
        var includedIds = new HashSet<string>();

        foreach (var id in nodeIds)
        {
            var node = graph.TryGetNode(id);
            if (node is not null && includedIds.Add(id))
                subgraph.AddNode(node);
        }

        foreach (var edge in graph.AllEdges)
        {
            if (includedIds.Contains(edge.SourceId) && includedIds.Contains(edge.TargetId))
                subgraph.AddEdge(edge);
        }

        return subgraph;
    }

    private static List<string> ReconstructPath(Dictionary<string, string> parent, string fromId, string toId)
    {
        var path = new List<string>();
        var current = toId;

        while (current != fromId)
        {
            path.Add(current);
            current = parent[current];
        }

        path.Add(fromId);
        path.Reverse();
        return path;
    }
}
