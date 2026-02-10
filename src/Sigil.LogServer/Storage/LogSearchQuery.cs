namespace Sigil.LogServer.Storage;

public sealed class LogSearchQuery
{
    public string? KeyId { get; set; }
    public string? ArtifactName { get; set; }
    public string? ArtifactDigest { get; set; }
    public int Limit { get; set; } = 50;
    public int Offset { get; set; }
}
