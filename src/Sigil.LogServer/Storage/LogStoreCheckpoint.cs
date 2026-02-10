namespace Sigil.LogServer.Storage;

public sealed class LogStoreCheckpoint
{
    public long Id { get; set; }
    public required long TreeSize { get; set; }
    public required string RootHash { get; set; }
    public required string Timestamp { get; set; }
    public required string Signature { get; set; }
}
