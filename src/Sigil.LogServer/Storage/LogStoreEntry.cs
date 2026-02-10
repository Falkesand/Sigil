namespace Sigil.LogServer.Storage;

public sealed class LogStoreEntry
{
    public long Id { get; set; }
    public required string Timestamp { get; set; }
    public required string KeyId { get; set; }
    public required string Algorithm { get; set; }
    public required string ArtifactName { get; set; }
    public required string ArtifactDigest { get; set; }
    public required string SignatureDigest { get; set; }
    public string? Label { get; set; }
    public required string LeafHash { get; set; }
    public required string RawJson { get; set; }
}
