namespace Sigil.Signing;

/// <summary>
/// Result of verifying a single file within a manifest.
/// </summary>
public sealed class FileVerificationResult
{
    public required string Name { get; init; }
    public required bool DigestMatch { get; init; }
    public string? Error { get; init; }
}
