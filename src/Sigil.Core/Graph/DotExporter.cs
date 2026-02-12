using System.Globalization;
using System.Text;

namespace Sigil.Graph;

public static class DotExporter
{
    public static string Export(TrustGraph graph)
    {
        ArgumentNullException.ThrowIfNull(graph);

        var sb = new StringBuilder();
        sb.AppendLine("digraph TrustGraph {");
        sb.AppendLine("    rankdir=LR;");
        sb.AppendLine();

        foreach (var node in graph.AllNodes)
        {
            var shape = node.Type switch
            {
                GraphNodeType.Key => "hexagon",
                GraphNodeType.Artifact => "box",
                GraphNodeType.Identity => "ellipse",
                GraphNodeType.Attestation => "diamond",
                GraphNodeType.LogRecord => "cylinder",
                _ => "box"
            };
            var escapedLabel = EscapeDotString(node.Label);
            var escapedId = EscapeDotString(node.Id);
            sb.AppendLine(CultureInfo.InvariantCulture, $"    \"{escapedId}\" [label=\"{escapedLabel}\", shape={shape}];");
        }

        sb.AppendLine();

        foreach (var edge in graph.AllEdges)
        {
            var escapedSource = EscapeDotString(edge.SourceId);
            var escapedTarget = EscapeDotString(edge.TargetId);
            var escapedLabel = EscapeDotString(edge.Label);
            var color = edge.Type == GraphEdgeType.RevokedAt ? ", color=red, fontcolor=red" : "";
            sb.AppendLine(CultureInfo.InvariantCulture, $"    \"{escapedSource}\" -> \"{escapedTarget}\" [label=\"{escapedLabel}\"{color}];");
        }

        sb.AppendLine("}");
        return sb.ToString();
    }

    private static string EscapeDotString(string value)
    {
        return value
            .Replace("\\", "\\\\")
            .Replace("\"", "\\\"")
            .Replace("\n", "\\n")
            .Replace("\r", "\\r");
    }
}
