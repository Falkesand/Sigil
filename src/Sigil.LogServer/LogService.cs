using System.Text.Json;
using System.Text.Json.Serialization;
using Org.Webpki.JsonCanonicalizer;
using Sigil.LogServer.Storage;
using Sigil.Transparency;

namespace Sigil.LogServer;

public sealed class LogService : IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private readonly ILogStore _store;
    private readonly ICheckpointSigner _signer;
    private readonly SemaphoreSlim _appendLock = new(1, 1);
    private readonly List<byte[]> _leafHashCache = [];
    private bool _cacheInitialized;

    public LogService(ILogStore store, ICheckpointSigner signer)
    {
        _store = store;
        _signer = signer;
    }

    public async Task<AppendResult> AppendAsync(AppendRequest request, CancellationToken ct = default)
    {
        await _appendLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await EnsureCacheInitializedAsync(ct).ConfigureAwait(false);

            // Check for duplicate
            var signatureDigest = ComputeSignatureDigest(request.SignatureValue);
            if (await _store.SignatureDigestExistsAsync(signatureDigest, ct).ConfigureAwait(false))
                return AppendResult.Duplicate();

            var entryCount = _leafHashCache.Count;
            var timestamp = DateTime.UtcNow.ToString("o");

            var leafHash = ComputeLeafHash(entryCount, timestamp, request);

            var rawJson = JsonSerializer.Serialize(new
            {
                keyId = request.KeyId,
                algorithm = request.Algorithm,
                publicKey = request.PublicKey,
                signatureValue = request.SignatureValue,
                artifactName = request.ArtifactName,
                artifactDigest = request.ArtifactDigest,
                label = request.Label
            }, JsonOptions);

            var entry = new LogStoreEntry
            {
                Timestamp = timestamp,
                KeyId = request.KeyId,
                Algorithm = request.Algorithm,
                ArtifactName = request.ArtifactName,
                ArtifactDigest = request.ArtifactDigest,
                SignatureDigest = signatureDigest,
                Label = request.Label,
                LeafHash = leafHash,
                RawJson = rawJson
            };

            var index = await _store.AppendEntryAsync(entry, ct).ConfigureAwait(false);

            // Update in-memory cache (append-only)
            var newLeafHashBytes = Convert.FromHexString(leafHash);
            _leafHashCache.Add(newLeafHashBytes);

            var rootHash = Convert.ToHexStringLower(MerkleTree.ComputeRoot(_leafHashCache));

            var checkpointTimestamp = DateTime.UtcNow.ToString("o");
            var signedCheckpoint = _signer.SignCheckpoint(_leafHashCache.Count, rootHash, checkpointTimestamp);

            var checkpoint = new LogStoreCheckpoint
            {
                TreeSize = _leafHashCache.Count,
                RootHash = rootHash,
                Timestamp = checkpointTimestamp,
                Signature = signedCheckpoint
            };
            await _store.SaveCheckpointAsync(checkpoint, ct).ConfigureAwait(false);

            // Generate inclusion proof for the new entry
            var proof = MerkleTree.GenerateInclusionProof((int)(index - 1), _leafHashCache);

            return AppendResult.Success(index, leafHash, signedCheckpoint, proof);
        }
        finally
        {
            _appendLock.Release();
        }
    }

    public async Task<InclusionProof?> GetInclusionProofAsync(long leafIndex, CancellationToken ct = default)
    {
        await EnsureCacheInitializedAsync(ct).ConfigureAwait(false);

        if (leafIndex < 0 || leafIndex >= _leafHashCache.Count)
            return null;

        return MerkleTree.GenerateInclusionProof((int)leafIndex, _leafHashCache);
    }

    public async Task<ConsistencyProof?> GetConsistencyProofAsync(long oldSize, CancellationToken ct = default)
    {
        await EnsureCacheInitializedAsync(ct).ConfigureAwait(false);

        if (oldSize < 0 || oldSize > _leafHashCache.Count)
            return null;

        return MerkleTree.GenerateConsistencyProof((int)oldSize, _leafHashCache);
    }

    private async Task EnsureCacheInitializedAsync(CancellationToken ct)
    {
        if (_cacheInitialized)
            return;

        var leafHashes = await _store.GetLeafHashesAsync(ct).ConfigureAwait(false);
        _leafHashCache.Clear();
        _leafHashCache.AddRange(leafHashes.Select(Convert.FromHexString));
        _cacheInitialized = true;
    }

    public void Dispose()
    {
        _appendLock.Dispose();
    }

    private static string ComputeSignatureDigest(string signatureValueBase64)
    {
        var signatureBytes = Convert.FromBase64String(signatureValueBase64);
        return "sha256:" + Sigil.Crypto.HashAlgorithms.Sha256Hex(signatureBytes);
    }

    private static string ComputeLeafHash(long entryIndex, string timestamp, AppendRequest request)
    {
        var hashInput = new Dictionary<string, object?>
        {
            ["index"] = entryIndex,
            ["timestamp"] = timestamp,
            ["keyId"] = request.KeyId,
            ["algorithm"] = request.Algorithm,
            ["artifactName"] = request.ArtifactName,
            ["artifactDigest"] = request.ArtifactDigest,
            ["signatureDigest"] = ComputeSignatureDigest(request.SignatureValue)
        };

        if (request.Label is not null)
            hashInput["label"] = request.Label;

        var json = JsonSerializer.Serialize(hashInput, JsonOptions);
        var canonical = new JsonCanonicalizer(json).GetEncodedUTF8();
        var leafHashBytes = MerkleTree.ComputeLeafHash(canonical);
        return Convert.ToHexStringLower(leafHashBytes);
    }
}
