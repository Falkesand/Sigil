using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Sigil.Graph;

/// <summary>
/// Analyzes the impact of a key compromise on a trust graph.
/// </summary>
public static class ImpactAnalyzer
{
    /// <summary>
    /// Analyzes the impact of a key compromise for the specified key node.
    /// </summary>
    public static GraphResult<ImpactReport> Analyze(TrustGraph graph, string keyId)
    {
        ArgumentNullException.ThrowIfNull(graph);
        ArgumentNullException.ThrowIfNull(keyId);

        var keyNode = graph.TryGetNode(keyId);
        if (keyNode is null)
            return GraphResult<ImpactReport>.Fail(GraphErrorKind.NodeNotFound, $"Node '{keyId}' not found.");

        // Extract fingerprint from node ID (e.g. "key:sha256:abc..." → "sha256:abc...")
        var fingerprint = keyId.StartsWith("key:", StringComparison.Ordinal) ? keyId["key:".Length..] : keyId;

        // Check revocation status via outgoing RevokedAt edges
        string? revokedAt = null;
        string? revocationReason = null;
        var isRevoked = false;

        foreach (var edge in graph.GetOutgoingEdges(keyId))
        {
            if (edge.Type == GraphEdgeType.RevokedAt)
            {
                isRevoked = true;
                edge.Properties.TryGetValue("revokedAt", out revokedAt);
                edge.Properties.TryGetValue("reason", out revocationReason);
                break;
            }
        }

        // Direct artifacts: nodes that have a SignedBy edge pointing to this key
        var signedByResult = GraphQuery.SignedBy(graph, keyId);
        var directArtifacts = signedByResult.IsSuccess ? signedByResult.Value : (IReadOnlyList<string>)[];

        // Endorsed keys (downstream): keys that have EndorsedBy edges pointing to this key
        // (meaning this key endorsed them — they depend on this key's trust)
        var endorsedKeys = new List<string>();
        foreach (var edge in graph.GetIncomingEdges(keyId))
        {
            if (edge.Type == GraphEdgeType.EndorsedBy)
                endorsedKeys.Add(edge.SourceId);
        }

        // Transitive artifacts: BFS through endorsed keys to find all downstream artifacts
        var transitiveArtifacts = new List<string>();
        var transitiveArtifactSet = new HashSet<string>();
        var directArtifactSet = new HashSet<string>(directArtifacts);
        var visitedKeys = new HashSet<string> { keyId };
        var queue = new Queue<string>(endorsedKeys);

        foreach (var ek in endorsedKeys)
            visitedKeys.Add(ek);

        while (queue.Count > 0)
        {
            var current = queue.Dequeue();
            var currentSigned = GraphQuery.SignedBy(graph, current);
            if (currentSigned.IsSuccess)
            {
                foreach (var artifact in currentSigned.Value)
                {
                    if (!directArtifactSet.Contains(artifact) && transitiveArtifactSet.Add(artifact))
                        transitiveArtifacts.Add(artifact);
                }
            }

            // Continue BFS through further endorsement chains
            foreach (var edge in graph.GetIncomingEdges(current))
            {
                if (edge.Type == GraphEdgeType.EndorsedBy && visitedKeys.Add(edge.SourceId))
                    queue.Enqueue(edge.SourceId);
            }
        }

        // Endorsed-by keys (upstream): keys that this key has EndorsedBy edges to
        var endorsedByKeys = new List<string>();
        foreach (var edge in graph.GetOutgoingEdges(keyId))
        {
            if (edge.Type == GraphEdgeType.EndorsedBy)
                endorsedByKeys.Add(edge.TargetId);
        }

        // Bound identities: identity nodes connected via IdentityBoundTo edges
        var boundIdentities = new List<string>();
        foreach (var edge in graph.GetOutgoingEdges(keyId))
        {
            if (edge.Type == GraphEdgeType.IdentityBoundTo)
                boundIdentities.Add(edge.TargetId);
        }

        // Generate recommendations
        var recommendations = new List<string>();
        if (!isRevoked)
            recommendations.Add("Revoke this key in all trust bundles containing it");

        if (directArtifacts.Count > 0)
            recommendations.Add($"Re-sign {directArtifacts.Count} directly signed artifact{Plural(directArtifacts.Count)} with a new key");

        if (transitiveArtifacts.Count > 0)
            recommendations.Add($"Re-evaluate {transitiveArtifacts.Count} transitively affected artifact{Plural(transitiveArtifacts.Count)}");

        if (endorsedKeys.Count > 0)
            recommendations.Add($"Review endorsement of {endorsedKeys.Count} downstream key{Plural(endorsedKeys.Count)}");

        recommendations.Add("Rotate to a new key pair");
        recommendations.Add("Audit transparency logs for unauthorized signatures");

        var report = new ImpactReport
        {
            KeyId = keyId,
            Fingerprint = fingerprint,
            KeyLabel = keyNode.Label != fingerprint ? keyNode.Label : null,
            IsRevoked = isRevoked,
            RevokedAt = revokedAt,
            RevocationReason = revocationReason,
            DirectArtifacts = directArtifacts,
            TransitiveArtifacts = transitiveArtifacts,
            EndorsedKeys = endorsedKeys,
            EndorsedByKeys = endorsedByKeys,
            BoundIdentities = boundIdentities,
            Recommendations = recommendations,
        };

        return GraphResult<ImpactReport>.Ok(report);
    }

    /// <summary>
    /// Formats an impact report as human-readable text.
    /// </summary>
    public static string FormatText(ImpactReport report)
    {
        ArgumentNullException.ThrowIfNull(report);

        var inv = CultureInfo.InvariantCulture;
        var sb = new StringBuilder();
        sb.AppendLine("Key Compromise Impact Report");
        sb.AppendLine("=============================");
        sb.AppendLine(inv, $"Key:          {report.Fingerprint}");

        if (report.KeyLabel is not null)
            sb.AppendLine(inv, $"Label:        {report.KeyLabel}");

        if (report.IsRevoked)
        {
            var revDetails = report.RevokedAt ?? "unknown time";
            if (report.RevocationReason is not null)
                revDetails = string.Concat(revDetails, ", reason: ", report.RevocationReason);
            sb.AppendLine(inv, $"Status:       REVOKED ({revDetails})");
        }
        else
        {
            sb.AppendLine("Status:       ACTIVE (not yet revoked)");
        }

        sb.AppendLine();
        sb.AppendLine(inv, $"Direct Impact: {report.DirectArtifacts.Count} artifact{Plural(report.DirectArtifacts.Count)}");
        foreach (var artifact in report.DirectArtifacts)
            sb.AppendLine(inv, $"  - {artifact}");

        if (report.TransitiveArtifacts.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine(inv, $"Transitive Impact: {report.TransitiveArtifacts.Count} artifact{Plural(report.TransitiveArtifacts.Count)} (via endorsement chain)");
            foreach (var artifact in report.TransitiveArtifacts)
                sb.AppendLine(inv, $"  - {artifact}");
        }

        if (report.EndorsedKeys.Count > 0 || report.EndorsedByKeys.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("Endorsement Chain:");

            if (report.EndorsedKeys.Count > 0)
            {
                sb.AppendLine(inv, $"  Endorses: {report.EndorsedKeys.Count} key{Plural(report.EndorsedKeys.Count)}");
                foreach (var key in report.EndorsedKeys)
                    sb.AppendLine(inv, $"    - {key}");
            }

            if (report.EndorsedByKeys.Count > 0)
            {
                sb.AppendLine(inv, $"  Endorsed by: {report.EndorsedByKeys.Count} key{Plural(report.EndorsedByKeys.Count)}");
                foreach (var key in report.EndorsedByKeys)
                    sb.AppendLine(inv, $"    - {key}");
            }
        }

        if (report.BoundIdentities.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine(inv, $"Bound Identities: {report.BoundIdentities.Count}");
            foreach (var identity in report.BoundIdentities)
                sb.AppendLine(inv, $"  - {identity}");
        }

        sb.AppendLine();
        sb.AppendLine("Recommendations:");
        for (var i = 0; i < report.Recommendations.Count; i++)
            sb.AppendLine(inv, $"  {i + 1}. {report.Recommendations[i]}");

        return sb.ToString();
    }

    /// <summary>
    /// Formats an impact report as JSON for machine consumption.
    /// </summary>
    public static string FormatJson(ImpactReport report)
    {
        ArgumentNullException.ThrowIfNull(report);

        var dto = new ImpactReportDto
        {
            KeyId = report.KeyId,
            Fingerprint = report.Fingerprint,
            KeyLabel = report.KeyLabel,
            IsRevoked = report.IsRevoked,
            RevokedAt = report.RevokedAt,
            RevocationReason = report.RevocationReason,
            DirectArtifacts = report.DirectArtifacts.ToList(),
            TransitiveArtifacts = report.TransitiveArtifacts.ToList(),
            EndorsedKeys = report.EndorsedKeys.ToList(),
            EndorsedByKeys = report.EndorsedByKeys.ToList(),
            BoundIdentities = report.BoundIdentities.ToList(),
            Recommendations = report.Recommendations.ToList(),
        };

        return JsonSerializer.Serialize(dto, JsonOptions);
    }

    private static string Plural(int count) => count == 1 ? "" : "s";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private sealed class ImpactReportDto
    {
        [JsonPropertyName("keyId")]
        public required string KeyId { get; init; }

        [JsonPropertyName("fingerprint")]
        public required string Fingerprint { get; init; }

        [JsonPropertyName("keyLabel")]
        public string? KeyLabel { get; init; }

        [JsonPropertyName("isRevoked")]
        public required bool IsRevoked { get; init; }

        [JsonPropertyName("revokedAt")]
        public string? RevokedAt { get; init; }

        [JsonPropertyName("revocationReason")]
        public string? RevocationReason { get; init; }

        [JsonPropertyName("directArtifacts")]
        public required List<string> DirectArtifacts { get; init; }

        [JsonPropertyName("transitiveArtifacts")]
        public required List<string> TransitiveArtifacts { get; init; }

        [JsonPropertyName("endorsedKeys")]
        public required List<string> EndorsedKeys { get; init; }

        [JsonPropertyName("endorsedByKeys")]
        public required List<string> EndorsedByKeys { get; init; }

        [JsonPropertyName("boundIdentities")]
        public required List<string> BoundIdentities { get; init; }

        [JsonPropertyName("recommendations")]
        public required List<string> Recommendations { get; init; }
    }
}
