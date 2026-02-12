namespace Sigil.Anomaly;

public sealed class AllowlistConfig
{
    public List<string> Signers { get; init; } = [];

    public List<string> OidcIdentities { get; init; } = [];

    public List<int> Hours { get; init; } = [];

    public List<string> Labels { get; init; } = [];
}
