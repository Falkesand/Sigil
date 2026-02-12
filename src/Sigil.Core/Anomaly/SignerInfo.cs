namespace Sigil.Anomaly;

public sealed class SignerInfo
{
    public int Count { get; init; }

    public required string Algorithm { get; init; }

    public DateTimeOffset LastSeen { get; init; }
}
