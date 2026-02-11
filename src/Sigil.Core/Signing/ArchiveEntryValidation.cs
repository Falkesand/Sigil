namespace Sigil.Signing;

/// <summary>
/// Result of verifying a single entry within an archive.
/// </summary>
public sealed class ArchiveEntryValidation
{
    public required string Name { get; init; }
    public required bool DigestMatch { get; init; }
    public string? Error { get; init; }
}
