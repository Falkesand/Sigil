using Sigil.Transparency;

namespace Sigil.LogServer;

public sealed class AppendResult
{
    public bool IsSuccess { get; private init; }
    public bool IsDuplicate { get; private init; }
    public long LogIndex { get; private init; }
    public string LeafHash { get; private init; } = "";
    public string SignedCheckpoint { get; private init; } = "";
    public InclusionProof? InclusionProof { get; private init; }

    public static AppendResult Success(long index, string leafHash, string signedCheckpoint, InclusionProof proof)
        => new()
        {
            IsSuccess = true,
            LogIndex = index,
            LeafHash = leafHash,
            SignedCheckpoint = signedCheckpoint,
            InclusionProof = proof
        };

    public static AppendResult Duplicate() => new() { IsDuplicate = true };
}
