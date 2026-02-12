namespace Sigil.Pe;

/// <summary>
/// Result of verifying an Authenticode signature embedded in a PE file.
/// </summary>
public sealed class AuthenticodeVerifyResult
{
    public required bool IsValid { get; init; }
    public required string DigestAlgorithm { get; init; }
    public required string SubjectName { get; init; }
    public required string IssuerName { get; init; }
    public required string Thumbprint { get; init; }
    public DateTimeOffset? TimestampUtc { get; init; }
    public string? Error { get; init; }
}
