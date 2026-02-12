using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Sigil.Anomaly;

/// <summary>
/// Formats anomaly detection reports as human-readable text or machine-readable JSON.
/// </summary>
public static class AnomalyFormatter
{
    /// <summary>
    /// Formats an anomaly report as human-readable text.
    /// </summary>
    public static string FormatText(AnomalyReport report)
    {
        ArgumentNullException.ThrowIfNull(report);

        if (report.Findings.Count == 0)
            return "No anomalies detected.\n";

        var inv = CultureInfo.InvariantCulture;
        var sb = new StringBuilder();
        sb.AppendLine("Anomaly Detection Report");
        sb.AppendLine("========================");
        sb.AppendLine(inv, $"Artifact: {report.ArtifactName}");
        sb.AppendLine(inv, $"Findings: {report.Findings.Count}");
        sb.AppendLine();

        var grouped = report.Findings
            .OrderByDescending(f => f.Severity)
            .ToList();

        foreach (var finding in grouped)
        {
            var severity = finding.Severity switch
            {
                AnomalySeverity.Critical => "CRITICAL",
                AnomalySeverity.Warning => "WARNING",
                AnomalySeverity.Info => "INFO",
                _ => finding.Severity.ToString().ToUpperInvariant(),
            };

            sb.AppendLine(inv, $"  [{severity}] {finding.Message}");

            if (finding.Context is not null)
            {
                foreach (var kvp in finding.Context)
                {
                    sb.AppendLine(inv, $"           {kvp.Key}: {kvp.Value}");
                }
            }
        }

        return sb.ToString();
    }

    /// <summary>
    /// Formats an anomaly report as JSON for machine consumption.
    /// </summary>
    public static string FormatJson(AnomalyReport report)
    {
        ArgumentNullException.ThrowIfNull(report);

        var findingDtos = new List<FindingDto>(report.Findings.Count);
        foreach (var finding in report.Findings)
        {
            findingDtos.Add(new FindingDto
            {
                RuleName = finding.RuleName,
                Severity = finding.Severity,
                Message = finding.Message,
                Context = finding.Context,
            });
        }

        var dto = new ReportDto
        {
            ArtifactName = report.ArtifactName,
            Timestamp = report.Timestamp.ToString("O", CultureInfo.InvariantCulture),
            FindingCount = report.Findings.Count,
            Findings = findingDtos,
        };

        return JsonSerializer.Serialize(dto, JsonOptions);
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    private sealed class ReportDto
    {
        [JsonPropertyName("artifactName")]
        public required string ArtifactName { get; init; }

        [JsonPropertyName("timestamp")]
        public required string Timestamp { get; init; }

        [JsonPropertyName("findingCount")]
        public required int FindingCount { get; init; }

        [JsonPropertyName("findings")]
        public required List<FindingDto> Findings { get; init; }
    }

    private sealed class FindingDto
    {
        [JsonPropertyName("ruleName")]
        public required string RuleName { get; init; }

        [JsonPropertyName("severity")]
        public required AnomalySeverity Severity { get; init; }

        [JsonPropertyName("message")]
        public required string Message { get; init; }

        [JsonPropertyName("context")]
        public Dictionary<string, string>? Context { get; init; }
    }
}
