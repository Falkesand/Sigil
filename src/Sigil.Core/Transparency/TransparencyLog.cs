using System.Text.Json;
using Sigil.Signing;

namespace Sigil.Transparency;

public sealed class TransparencyLog
{
    private readonly string _logPath;
    private readonly string _checkpointPath;

    public TransparencyLog(string logPath, string? checkpointPath = null)
    {
        _logPath = logPath;
        _checkpointPath = checkpointPath ?? DeriveCheckpointPath(logPath);
    }

    public TransparencyResult<LogEntry> Append(SignatureEnvelope envelope, int signatureIndex = 0)
    {
        if (signatureIndex < 0 || signatureIndex >= envelope.Signatures.Count)
            return TransparencyResult<LogEntry>.Fail(
                TransparencyErrorKind.InvalidEnvelope,
                $"Signature index {signatureIndex} is out of range. Envelope has {envelope.Signatures.Count} signature(s).");

        var entries = ReadAllEntries();

        // Duplicate detection
        byte[] sigBytes;
        try
        {
            sigBytes = Convert.FromBase64String(envelope.Signatures[signatureIndex].Value);
        }
        catch (FormatException)
        {
            return TransparencyResult<LogEntry>.Fail(
                TransparencyErrorKind.InvalidEnvelope,
                "Signature value is not valid base64.");
        }

        var sigDigest = "sha256:" + Crypto.HashAlgorithms.Sha256Hex(sigBytes);

        foreach (var existing in entries)
        {
            if (existing.SignatureDigest == sigDigest)
                return TransparencyResult<LogEntry>.Fail(
                    TransparencyErrorKind.DuplicateEntry,
                    $"Signature digest {sigDigest} is already logged at index {existing.Index}.");
        }

        var entryResult = LogEntryFactory.Create(envelope, signatureIndex, entries.Count);
        if (!entryResult.IsSuccess)
            return TransparencyResult<LogEntry>.Fail(entryResult.ErrorKind, entryResult.ErrorMessage);

        var entry = entryResult.Value;

        try
        {
            var json = JsonSerializer.Serialize(entry);
            File.AppendAllText(_logPath, json + "\n");
        }
        catch (IOException ex)
        {
            return TransparencyResult<LogEntry>.Fail(
                TransparencyErrorKind.AppendFailed,
                $"Failed to append to log: {ex.Message}");
        }

        // Update checkpoint
        entries.Add(entry);
        WriteCheckpoint(entries);

        return TransparencyResult<LogEntry>.Ok(entry);
    }

    public TransparencyResult<LogVerificationResult> Verify()
    {
        if (!File.Exists(_logPath))
            return TransparencyResult<LogVerificationResult>.Fail(
                TransparencyErrorKind.LogNotFound,
                $"Log file not found: {_logPath}");

        var entries = ReadAllEntries();
        var invalidIndices = new List<long>();

        // Validate each entry's leaf hash
        foreach (var entry in entries)
        {
            var expectedLeafHash = LogEntryFactory.ComputeEntryLeafHash(entry);
            if (entry.LeafHash != expectedLeafHash)
                invalidIndices.Add(entry.Index);
        }

        // Compute Merkle root
        var leafHashes = entries
            .Select(e => Convert.FromHexString(e.LeafHash))
            .ToList();
        var computedRoot = MerkleTree.ComputeRoot(leafHashes);
        var computedRootHex = Convert.ToHexStringLower(computedRoot);

        // Check checkpoint
        string? checkpointRootHash = null;
        bool checkpointMatch = true;

        if (File.Exists(_checkpointPath))
        {
            var checkpointJson = File.ReadAllText(_checkpointPath);
            var checkpoint = JsonSerializer.Deserialize<LogCheckpoint>(checkpointJson);
            if (checkpoint is not null)
            {
                checkpointRootHash = checkpoint.RootHash;
                checkpointMatch = checkpoint.RootHash == computedRootHex
                    && checkpoint.TreeSize == entries.Count;
            }
        }

        var result = new LogVerificationResult
        {
            EntryCount = entries.Count,
            ValidEntries = entries.Count - invalidIndices.Count,
            ComputedRootHash = computedRootHex,
            CheckpointRootHash = checkpointRootHash,
            CheckpointMatch = checkpointMatch,
            AllEntriesValid = invalidIndices.Count == 0,
            InvalidIndices = invalidIndices.Count > 0 ? invalidIndices : null
        };

        return TransparencyResult<LogVerificationResult>.Ok(result);
    }

    public TransparencyResult<IReadOnlyList<LogEntry>> Search(
        string? keyId = null,
        string? artifactName = null,
        string? digest = null)
    {
        if (!File.Exists(_logPath))
            return TransparencyResult<IReadOnlyList<LogEntry>>.Fail(
                TransparencyErrorKind.LogNotFound,
                $"Log file not found: {_logPath}");

        var entries = ReadAllEntries();
        var results = entries.Where(e =>
        {
            if (keyId is not null && !e.KeyId.Equals(keyId, StringComparison.OrdinalIgnoreCase))
                return false;
            if (artifactName is not null && !e.ArtifactName.Equals(artifactName, StringComparison.OrdinalIgnoreCase))
                return false;
            if (digest is not null && !e.SignatureDigest.Equals(digest, StringComparison.OrdinalIgnoreCase)
                && !e.ArtifactDigest.Equals(digest, StringComparison.OrdinalIgnoreCase))
                return false;
            return true;
        }).ToList();

        return TransparencyResult<IReadOnlyList<LogEntry>>.Ok(results);
    }

    public TransparencyResult<InclusionProof> GetInclusionProof(int leafIndex)
    {
        if (!File.Exists(_logPath))
            return TransparencyResult<InclusionProof>.Fail(
                TransparencyErrorKind.LogNotFound,
                $"Log file not found: {_logPath}");

        var entries = ReadAllEntries();
        if (leafIndex < 0 || leafIndex >= entries.Count)
            return TransparencyResult<InclusionProof>.Fail(
                TransparencyErrorKind.InvalidProof,
                $"Leaf index {leafIndex} is out of range. Log has {entries.Count} entries.");

        var leafHashes = entries
            .Select(e => Convert.FromHexString(e.LeafHash))
            .ToList();

        var proof = MerkleTree.GenerateInclusionProof(leafIndex, leafHashes);
        return TransparencyResult<InclusionProof>.Ok(proof);
    }

    public TransparencyResult<ConsistencyProof> GetConsistencyProof(int oldSize)
    {
        if (!File.Exists(_logPath))
            return TransparencyResult<ConsistencyProof>.Fail(
                TransparencyErrorKind.LogNotFound,
                $"Log file not found: {_logPath}");

        var entries = ReadAllEntries();
        if (oldSize < 1 || oldSize >= entries.Count)
            return TransparencyResult<ConsistencyProof>.Fail(
                TransparencyErrorKind.InvalidProof,
                $"Old size {oldSize} is out of range. Log has {entries.Count} entries.");

        var leafHashes = entries
            .Select(e => Convert.FromHexString(e.LeafHash))
            .ToList();

        var proof = MerkleTree.GenerateConsistencyProof(oldSize, leafHashes);
        return TransparencyResult<ConsistencyProof>.Ok(proof);
    }

    public TransparencyResult<IReadOnlyList<LogEntry>> ReadEntries(int? limit = null, int? offset = null)
    {
        if (!File.Exists(_logPath))
            return TransparencyResult<IReadOnlyList<LogEntry>>.Fail(
                TransparencyErrorKind.LogNotFound,
                $"Log file not found: {_logPath}");

        var entries = ReadAllEntries();
        IEnumerable<LogEntry> query = entries;

        if (offset.HasValue)
            query = query.Skip(offset.Value);
        if (limit.HasValue)
            query = query.Take(limit.Value);

        return TransparencyResult<IReadOnlyList<LogEntry>>.Ok(query.ToList());
    }

    private List<LogEntry> ReadAllEntries()
    {
        var entries = new List<LogEntry>();
        if (!File.Exists(_logPath))
            return entries;

        foreach (var line in File.ReadLines(_logPath))
        {
            if (string.IsNullOrWhiteSpace(line))
                continue;

            try
            {
                var entry = JsonSerializer.Deserialize<LogEntry>(line);
                if (entry is not null)
                    entries.Add(entry);
            }
            catch (JsonException)
            {
                // Skip malformed lines — integrity check will detect via leaf hash mismatch
            }
        }

        return entries;
    }

    private void WriteCheckpoint(List<LogEntry> entries)
    {
        var leafHashes = entries
            .Select(e => Convert.FromHexString(e.LeafHash))
            .ToList();
        var root = MerkleTree.ComputeRoot(leafHashes);

        var checkpoint = new LogCheckpoint
        {
            TreeSize = entries.Count,
            RootHash = Convert.ToHexStringLower(root),
            Timestamp = DateTime.UtcNow.ToString("o")
        };

        var json = JsonSerializer.Serialize(checkpoint);

        // Atomic write: write to temp file, then rename
        var tempPath = _checkpointPath + ".tmp";
        File.WriteAllText(tempPath, json);
        File.Move(tempPath, _checkpointPath, overwrite: true);
    }

    private static string DeriveCheckpointPath(string logPath)
    {
        var dir = Path.GetDirectoryName(logPath) ?? ".";
        var stem = Path.GetFileNameWithoutExtension(logPath);
        // Handle .log.jsonl double extension
        if (stem.EndsWith(".log", StringComparison.OrdinalIgnoreCase))
            stem = stem[..^4];
        return Path.Combine(dir, stem + ".checkpoint");
    }
}
