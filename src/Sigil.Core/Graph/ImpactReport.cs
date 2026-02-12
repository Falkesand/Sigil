namespace Sigil.Graph;

/// <summary>
/// Structured result of a key compromise impact analysis.
/// </summary>
public sealed class ImpactReport
{
    public required string KeyId { get; init; }
    public required string Fingerprint { get; init; }
    public required string? KeyLabel { get; init; }
    public required bool IsRevoked { get; init; }
    public required string? RevokedAt { get; init; }
    public required string? RevocationReason { get; init; }
    public required IReadOnlyList<string> DirectArtifacts { get; init; }
    public required IReadOnlyList<string> TransitiveArtifacts { get; init; }
    public required IReadOnlyList<string> EndorsedKeys { get; init; }
    public required IReadOnlyList<string> EndorsedByKeys { get; init; }
    public required IReadOnlyList<string> BoundIdentities { get; init; }
    public required IReadOnlyList<string> Recommendations { get; init; }
}
