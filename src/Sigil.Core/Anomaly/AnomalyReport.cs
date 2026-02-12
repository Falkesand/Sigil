namespace Sigil.Anomaly;

public sealed class AnomalyReport
{
    public required string ArtifactName { get; init; }

    public required DateTimeOffset Timestamp { get; init; }

    public required IReadOnlyList<AnomalyFinding> Findings { get; init; }
}
