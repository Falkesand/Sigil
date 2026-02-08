using Sigil.Timestamping;

namespace Sigil.Attestation;

/// <summary>
/// Result of verifying a single DSSE signature entry.
/// </summary>
public sealed class AttestationSignatureResult
{
    public required string KeyId { get; init; }
    public required bool IsValid { get; init; }
    public string? Algorithm { get; init; }
    public string? Error { get; init; }
    public TimestampVerificationInfo? TimestampInfo { get; init; }
}
