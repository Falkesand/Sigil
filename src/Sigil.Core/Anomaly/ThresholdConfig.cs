namespace Sigil.Anomaly;

public sealed class ThresholdConfig
{
    public AnomalySeverity NewSignerSeverity { get; init; } = AnomalySeverity.Warning;

    public AnomalySeverity OffHoursSeverity { get; init; } = AnomalySeverity.Warning;

    public AnomalySeverity UnknownOidcSeverity { get; init; } = AnomalySeverity.Critical;

    public AnomalySeverity UnknownAlgorithmSeverity { get; init; } = AnomalySeverity.Warning;

    public AnomalySeverity UnknownLabelSeverity { get; init; } = AnomalySeverity.Info;
}
