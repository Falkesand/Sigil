namespace Sigil.Signing;

/// <summary>
/// Describes a single entry within an archive.
/// </summary>
public readonly record struct ArchiveEntryInfo(string RelativePath, long Length, bool IsDirectory);
