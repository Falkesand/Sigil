namespace Sigil.Anomaly;

public sealed class BaselineModel
{
    public string Version { get; init; } = "1.0";

    public string Kind { get; init; } = "anomaly-baseline";

    public DateTimeOffset CreatedAt { get; init; }

    public DateTimeOffset UpdatedAt { get; init; }

    public int SampleCount { get; init; }

    public Dictionary<string, SignerInfo> Signers { get; init; } = new();

    public Dictionary<string, List<string>> OidcIdentities { get; init; } = new();

    public List<int> SigningHours { get; init; } = [];

    public List<string> Algorithms { get; init; } = [];

    public List<string> Labels { get; init; } = [];

    public AllowlistConfig Allowlist { get; init; } = new();

    public ThresholdConfig Thresholds { get; init; } = new();
}
