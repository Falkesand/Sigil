namespace Sigil.LogServer.Storage;

public interface ILogStore : IAsyncDisposable
{
    Task InitializeAsync(CancellationToken ct = default);
    Task<long> AppendEntryAsync(LogStoreEntry entry, CancellationToken ct = default);
    Task<LogStoreEntry?> GetEntryAsync(long index, CancellationToken ct = default);
    Task<IReadOnlyList<LogStoreEntry>> ListEntriesAsync(int limit, int offset, CancellationToken ct = default);
    Task<IReadOnlyList<LogStoreEntry>> SearchAsync(LogSearchQuery query, CancellationToken ct = default);
    Task<long> GetEntryCountAsync(CancellationToken ct = default);
    Task<IReadOnlyList<string>> GetLeafHashesAsync(CancellationToken ct = default);
    Task SaveCheckpointAsync(LogStoreCheckpoint checkpoint, CancellationToken ct = default);
    Task<LogStoreCheckpoint?> GetLatestCheckpointAsync(CancellationToken ct = default);
    Task<bool> SignatureDigestExistsAsync(string signatureDigest, CancellationToken ct = default);
}
