namespace Sigil.Trust;

/// <summary>
/// Trust evaluation result for a single signature.
/// </summary>
public sealed class SignatureTrustResult
{
    public required string KeyId { get; init; }
    public required TrustDecision Decision { get; init; }
    public string? DisplayName { get; init; }
    public string? Reason { get; init; }
}
