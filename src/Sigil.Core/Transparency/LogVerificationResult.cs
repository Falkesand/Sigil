namespace Sigil.Transparency;

public sealed class LogVerificationResult
{
    public required long EntryCount { get; init; }

    public required long ValidEntries { get; init; }

    public required string ComputedRootHash { get; init; }

    public string? CheckpointRootHash { get; init; }

    public required bool CheckpointMatch { get; init; }

    public required bool AllEntriesValid { get; init; }

    public IReadOnlyList<long>? InvalidIndices { get; init; }
}
