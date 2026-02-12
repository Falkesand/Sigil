namespace Sigil.Anomaly;

public sealed class AnomalyFinding
{
    public required string RuleName { get; init; }

    public required AnomalySeverity Severity { get; init; }

    public required string Message { get; init; }

    public Dictionary<string, string>? Context { get; init; }
}
