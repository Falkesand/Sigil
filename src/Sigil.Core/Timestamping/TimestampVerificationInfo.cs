namespace Sigil.Timestamping;

public sealed class TimestampVerificationInfo
{
    public required DateTimeOffset Timestamp { get; init; }
    public required bool IsValid { get; init; }
    public string? Error { get; init; }
}
