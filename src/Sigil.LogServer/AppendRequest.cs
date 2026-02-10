namespace Sigil.LogServer;

public sealed class AppendRequest
{
    public required string KeyId { get; init; }
    public required string Algorithm { get; init; }
    public required string PublicKey { get; init; }
    public required string SignatureValue { get; init; }
    public required string ArtifactName { get; init; }
    public required string ArtifactDigest { get; init; }
    public string? Label { get; init; }
}
