using Npgsql;

namespace Sigil.LogServer.Storage;

public sealed class PostgresLogStore : ILogStore
{
    private readonly string _connectionString;

    public PostgresLogStore(string connectionString)
    {
        _connectionString = connectionString;
    }

    private async Task<NpgsqlConnection> CreateConnectionAsync(CancellationToken ct)
    {
        var conn = new NpgsqlConnection(_connectionString);
        await conn.OpenAsync(ct).ConfigureAwait(false);
        return conn;
    }

    public async Task InitializeAsync(CancellationToken ct = default)
    {
        await using var connection = await CreateConnectionAsync(ct).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS log_entries (
                id BIGSERIAL PRIMARY KEY,
                timestamp TEXT NOT NULL,
                key_id TEXT NOT NULL,
                algorithm TEXT NOT NULL,
                artifact_name TEXT NOT NULL,
                artifact_digest TEXT NOT NULL,
                signature_digest TEXT NOT NULL UNIQUE,
                label TEXT,
                leaf_hash TEXT NOT NULL,
                raw_json JSONB NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_log_entries_key_id ON log_entries(key_id);
            CREATE INDEX IF NOT EXISTS idx_log_entries_artifact_name ON log_entries(artifact_name);
            CREATE INDEX IF NOT EXISTS idx_log_entries_artifact_digest ON log_entries(artifact_digest);
            CREATE INDEX IF NOT EXISTS idx_log_entries_signature_digest ON log_entries(signature_digest);

            CREATE TABLE IF NOT EXISTS checkpoints (
                id BIGSERIAL PRIMARY KEY,
                tree_size BIGINT NOT NULL,
                root_hash TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            """;
        await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    public async Task<long> AppendEntryAsync(LogStoreEntry entry, CancellationToken ct = default)
    {
        await using var connection = await CreateConnectionAsync(ct).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            INSERT INTO log_entries (timestamp, key_id, algorithm, artifact_name, artifact_digest, signature_digest, label, leaf_hash, raw_json)
            VALUES (@timestamp, @keyId, @algorithm, @artifactName, @artifactDigest, @signatureDigest, @label, @leafHash, @rawJson::jsonb)
            RETURNING id;
            """;
        cmd.Parameters.AddWithValue("@timestamp", entry.Timestamp);
        cmd.Parameters.AddWithValue("@keyId", entry.KeyId);
        cmd.Parameters.AddWithValue("@algorithm", entry.Algorithm);
        cmd.Parameters.AddWithValue("@artifactName", entry.ArtifactName);
        cmd.Parameters.AddWithValue("@artifactDigest", entry.ArtifactDigest);
        cmd.Parameters.AddWithValue("@signatureDigest", entry.SignatureDigest);
        cmd.Parameters.AddWithValue("@label", (object?)entry.Label ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@leafHash", entry.LeafHash);
        cmd.Parameters.AddWithValue("@rawJson", entry.RawJson);

        var result = await cmd.ExecuteScalarAsync(ct).ConfigureAwait(false);
        return (long)result!;
    }

    public async Task<LogStoreEntry?> GetEntryAsync(long index, CancellationToken ct = default)
    {
        await using var connection = await CreateConnectionAsync(ct).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT id, timestamp, key_id, algorithm, artifact_name, artifact_digest, signature_digest, label, leaf_hash, raw_json FROM log_entries WHERE id = @id;";
        cmd.Parameters.AddWithValue("@id", index);

        await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (!await reader.ReadAsync(ct).ConfigureAwait(false))
            return null;

        return ReadEntry(reader);
    }

    public async Task<IReadOnlyList<LogStoreEntry>> ListEntriesAsync(int limit, int offset, CancellationToken ct = default)
    {
        await using var connection = await CreateConnectionAsync(ct).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT id, timestamp, key_id, algorithm, artifact_name, artifact_digest, signature_digest, label, leaf_hash, raw_json FROM log_entries ORDER BY id LIMIT @limit OFFSET @offset;";
        cmd.Parameters.AddWithValue("@limit", limit);
        cmd.Parameters.AddWithValue("@offset", offset);

        return await ReadEntriesAsync(cmd, ct).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<LogStoreEntry>> SearchAsync(LogSearchQuery query, CancellationToken ct = default)
    {
        await using var connection = await CreateConnectionAsync(ct).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();

        var conditions = new List<string>();
        if (query.KeyId is not null)
        {
            conditions.Add("key_id = @keyId");
            cmd.Parameters.AddWithValue("@keyId", query.KeyId);
        }
        if (query.ArtifactName is not null)
        {
            conditions.Add("artifact_name = @artifactName");
            cmd.Parameters.AddWithValue("@artifactName", query.ArtifactName);
        }
        if (query.ArtifactDigest is not null)
        {
            conditions.Add("artifact_digest = @artifactDigest");
            cmd.Parameters.AddWithValue("@artifactDigest", query.ArtifactDigest);
        }

        var where = conditions.Count > 0 ? "WHERE " + string.Join(" AND ", conditions) : "";
        cmd.CommandText = $"SELECT id, timestamp, key_id, algorithm, artifact_name, artifact_digest, signature_digest, label, leaf_hash, raw_json FROM log_entries {where} ORDER BY id LIMIT @limit OFFSET @offset;";
        cmd.Parameters.AddWithValue("@limit", query.Limit);
        cmd.Parameters.AddWithValue("@offset", query.Offset);

        return await ReadEntriesAsync(cmd, ct).ConfigureAwait(false);
    }

    public async Task<long> GetEntryCountAsync(CancellationToken ct = default)
    {
        await using var connection = await CreateConnectionAsync(ct).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM log_entries;";
        var result = await cmd.ExecuteScalarAsync(ct).ConfigureAwait(false);
        return (long)result!;
    }

    public async Task<IReadOnlyList<string>> GetLeafHashesAsync(CancellationToken ct = default)
    {
        await using var connection = await CreateConnectionAsync(ct).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT leaf_hash FROM log_entries ORDER BY id;";

        await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        var hashes = new List<string>();
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            hashes.Add(reader.GetString(0));
        }
        return hashes;
    }

    public async Task SaveCheckpointAsync(LogStoreCheckpoint checkpoint, CancellationToken ct = default)
    {
        await using var connection = await CreateConnectionAsync(ct).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            INSERT INTO checkpoints (tree_size, root_hash, timestamp, signature)
            VALUES (@treeSize, @rootHash, @timestamp, @signature);
            """;
        cmd.Parameters.AddWithValue("@treeSize", checkpoint.TreeSize);
        cmd.Parameters.AddWithValue("@rootHash", checkpoint.RootHash);
        cmd.Parameters.AddWithValue("@timestamp", checkpoint.Timestamp);
        cmd.Parameters.AddWithValue("@signature", checkpoint.Signature);

        await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    public async Task<LogStoreCheckpoint?> GetLatestCheckpointAsync(CancellationToken ct = default)
    {
        await using var connection = await CreateConnectionAsync(ct).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT id, tree_size, root_hash, timestamp, signature FROM checkpoints ORDER BY id DESC LIMIT 1;";

        await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (!await reader.ReadAsync(ct).ConfigureAwait(false))
            return null;

        return new LogStoreCheckpoint
        {
            Id = reader.GetInt64(0),
            TreeSize = reader.GetInt64(1),
            RootHash = reader.GetString(2),
            Timestamp = reader.GetString(3),
            Signature = reader.GetString(4)
        };
    }

    public async Task<bool> SignatureDigestExistsAsync(string signatureDigest, CancellationToken ct = default)
    {
        await using var connection = await CreateConnectionAsync(ct).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM log_entries WHERE signature_digest = @signatureDigest;";
        cmd.Parameters.AddWithValue("@signatureDigest", signatureDigest);

        var result = await cmd.ExecuteScalarAsync(ct).ConfigureAwait(false);
        return (long)result! > 0;
    }

    private static LogStoreEntry ReadEntry(NpgsqlDataReader reader)
    {
        return new LogStoreEntry
        {
            Id = reader.GetInt64(0),
            Timestamp = reader.GetString(1),
            KeyId = reader.GetString(2),
            Algorithm = reader.GetString(3),
            ArtifactName = reader.GetString(4),
            ArtifactDigest = reader.GetString(5),
            SignatureDigest = reader.GetString(6),
            Label = reader.IsDBNull(7) ? null : reader.GetString(7),
            LeafHash = reader.GetString(8),
            RawJson = reader.GetString(9)
        };
    }

    private static async Task<List<LogStoreEntry>> ReadEntriesAsync(NpgsqlCommand cmd, CancellationToken ct)
    {
        await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        var entries = new List<LogStoreEntry>();
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            entries.Add(ReadEntry(reader));
        }
        return entries;
    }

    public ValueTask DisposeAsync()
    {
        return ValueTask.CompletedTask;
    }
}
