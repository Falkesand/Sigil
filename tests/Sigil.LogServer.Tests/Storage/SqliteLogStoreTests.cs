#pragma warning disable CA1707 // Identifiers should not contain underscores
#pragma warning disable CA1816 // Dispose methods should call SuppressFinalize
#pragma warning disable CA1001 // Types that own disposable fields should be disposable (IAsyncLifetime handles disposal)

using Microsoft.Data.Sqlite;
using Sigil.LogServer.Storage;
using Xunit;

namespace Sigil.LogServer.Tests.Storage;

public sealed class SqliteLogStoreTests : IAsyncLifetime
{
    private string _dbPath = null!;
    private SqliteLogStore _store = null!;

    public async Task InitializeAsync()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"sigil-logstore-test-{Guid.NewGuid():N}.db");
        _store = new SqliteLogStore(_dbPath);
        await _store.InitializeAsync();
    }

    public async Task DisposeAsync()
    {
        await _store.DisposeAsync();
        try { File.Delete(_dbPath); } catch { /* best-effort cleanup */ }
    }

    [Fact]
    public async Task InitializeAsync_CreatesTablesSuccessfully()
    {
        // Arrange: Already initialized via IAsyncLifetime
        var entry = CreateTestEntry("key1", "artifact1", "digest1", "sig1");

        // Act: Try inserting an entry
        var id = await _store.AppendEntryAsync(entry);

        // Assert: Should succeed and return valid ID
        Assert.True(id > 0);

        // Verify we can read it back
        var retrieved = await _store.GetEntryAsync(id);
        Assert.NotNull(retrieved);
    }

    [Fact]
    public async Task AppendEntryAsync_ReturnsAutoIncrementId_StartingAtOne()
    {
        // Arrange
        var entry1 = CreateTestEntry("key1", "artifact1", "digest1", "sig1");
        var entry2 = CreateTestEntry("key2", "artifact2", "digest2", "sig2");

        // Act
        var id1 = await _store.AppendEntryAsync(entry1);
        var id2 = await _store.AppendEntryAsync(entry2);

        // Assert
        Assert.Equal(1, id1);
        Assert.Equal(2, id2);
    }

    [Fact]
    public async Task AppendEntryAsync_WithNullLabel_StoresSuccessfully()
    {
        // Arrange
        var entry = CreateTestEntry("key1", "artifact1", "digest1", "sig1", label: null);

        // Act
        var id = await _store.AppendEntryAsync(entry);

        // Assert
        var retrieved = await _store.GetEntryAsync(id);
        Assert.NotNull(retrieved);
        Assert.Null(retrieved.Label);
    }

    [Fact]
    public async Task AppendEntryAsync_DuplicateSignatureDigest_ThrowsSqliteException()
    {
        // Arrange
        var entry1 = CreateTestEntry("key1", "artifact1", "digest1", "duplicate-sig");
        var entry2 = CreateTestEntry("key2", "artifact2", "digest2", "duplicate-sig");

        await _store.AppendEntryAsync(entry1);

        // Act & Assert
        var ex = await Assert.ThrowsAsync<SqliteException>(() => _store.AppendEntryAsync(entry2));
        Assert.Contains("UNIQUE constraint failed", ex.Message);
    }

    [Fact]
    public async Task GetEntryAsync_NonExistentIndex_ReturnsNull()
    {
        // Act
        var result = await _store.GetEntryAsync(999);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task GetEntryAsync_ExistingEntry_ReturnsCorrectData()
    {
        // Arrange
        var entry = CreateTestEntry("key1", "artifact1", "digest1", "sig1", "test-label");
        var id = await _store.AppendEntryAsync(entry);

        // Act
        var retrieved = await _store.GetEntryAsync(id);

        // Assert
        Assert.NotNull(retrieved);
        Assert.Equal(id, retrieved.Id);
        Assert.Equal("key1", retrieved.KeyId);
        Assert.Equal("ecdsa-p256", retrieved.Algorithm);
        Assert.Equal("artifact1", retrieved.ArtifactName);
        Assert.Equal("digest1", retrieved.ArtifactDigest);
        Assert.Equal("sig1", retrieved.SignatureDigest);
        Assert.Equal("test-label", retrieved.Label);
        Assert.NotEmpty(retrieved.LeafHash);
        Assert.NotEmpty(retrieved.RawJson);
    }

    [Fact]
    public async Task ListEntriesAsync_WithLimitAndOffset_ReturnsCorrectSubset()
    {
        // Arrange
        for (int i = 1; i <= 10; i++)
        {
            var entry = CreateTestEntry($"key{i}", $"artifact{i}", $"digest{i}", $"sig{i}");
            await _store.AppendEntryAsync(entry);
        }

        // Act
        var page1 = await _store.ListEntriesAsync(limit: 3, offset: 0);
        var page2 = await _store.ListEntriesAsync(limit: 3, offset: 3);
        var page3 = await _store.ListEntriesAsync(limit: 3, offset: 6);

        // Assert
        Assert.Equal(3, page1.Count);
        Assert.Equal(3, page2.Count);
        Assert.Equal(3, page3.Count);

        Assert.Equal(1, page1[0].Id);
        Assert.Equal(4, page2[0].Id);
        Assert.Equal(7, page3[0].Id);
    }

    [Fact]
    public async Task SearchAsync_ByKeyId_ReturnsMatchingEntries()
    {
        // Arrange
        await _store.AppendEntryAsync(CreateTestEntry("key-a", "artifact1", "digest1", "sig1"));
        await _store.AppendEntryAsync(CreateTestEntry("key-b", "artifact2", "digest2", "sig2"));
        await _store.AppendEntryAsync(CreateTestEntry("key-a", "artifact3", "digest3", "sig3"));

        // Act
        var query = new LogSearchQuery { KeyId = "key-a" };
        var results = await _store.SearchAsync(query);

        // Assert
        Assert.Equal(2, results.Count);
        Assert.All(results, e => Assert.Equal("key-a", e.KeyId));
    }

    [Fact]
    public async Task SearchAsync_ByArtifactName_ReturnsMatchingEntries()
    {
        // Arrange
        await _store.AppendEntryAsync(CreateTestEntry("key1", "app.dll", "digest1", "sig1"));
        await _store.AppendEntryAsync(CreateTestEntry("key2", "lib.dll", "digest2", "sig2"));
        await _store.AppendEntryAsync(CreateTestEntry("key3", "app.dll", "digest3", "sig3"));

        // Act
        var query = new LogSearchQuery { ArtifactName = "app.dll" };
        var results = await _store.SearchAsync(query);

        // Assert
        Assert.Equal(2, results.Count);
        Assert.All(results, e => Assert.Equal("app.dll", e.ArtifactName));
    }

    [Fact]
    public async Task SearchAsync_ByArtifactDigest_ReturnsMatchingEntries()
    {
        // Arrange
        await _store.AppendEntryAsync(CreateTestEntry("key1", "artifact1", "sha256:abc123", "sig1"));
        await _store.AppendEntryAsync(CreateTestEntry("key2", "artifact2", "sha256:def456", "sig2"));
        await _store.AppendEntryAsync(CreateTestEntry("key3", "artifact3", "sha256:abc123", "sig3"));

        // Act
        var query = new LogSearchQuery { ArtifactDigest = "sha256:abc123" };
        var results = await _store.SearchAsync(query);

        // Assert
        Assert.Equal(2, results.Count);
        Assert.All(results, e => Assert.Equal("sha256:abc123", e.ArtifactDigest));
    }

    [Fact]
    public async Task SearchAsync_MultipleCriteria_ReturnsIntersection()
    {
        // Arrange
        await _store.AppendEntryAsync(CreateTestEntry("key-a", "artifact1", "digest1", "sig1"));
        await _store.AppendEntryAsync(CreateTestEntry("key-a", "artifact2", "digest2", "sig2"));
        await _store.AppendEntryAsync(CreateTestEntry("key-b", "artifact1", "digest1", "sig3"));

        // Act
        var query = new LogSearchQuery { KeyId = "key-a", ArtifactName = "artifact1" };
        var results = await _store.SearchAsync(query);

        // Assert
        Assert.Single(results);
        Assert.Equal("key-a", results[0].KeyId);
        Assert.Equal("artifact1", results[0].ArtifactName);
    }

    [Fact]
    public async Task SearchAsync_WithLimitAndOffset_PaginatesResults()
    {
        // Arrange
        for (int i = 1; i <= 10; i++)
        {
            await _store.AppendEntryAsync(CreateTestEntry("same-key", $"artifact{i}", $"digest{i}", $"sig{i}"));
        }

        // Act
        var query1 = new LogSearchQuery { KeyId = "same-key", Limit = 3, Offset = 0 };
        var query2 = new LogSearchQuery { KeyId = "same-key", Limit = 3, Offset = 3 };

        var page1 = await _store.SearchAsync(query1);
        var page2 = await _store.SearchAsync(query2);

        // Assert
        Assert.Equal(3, page1.Count);
        Assert.Equal(3, page2.Count);
        Assert.NotEqual(page1[0].Id, page2[0].Id);
    }

    [Fact]
    public async Task GetEntryCountAsync_ReturnsCorrectCount()
    {
        // Arrange
        Assert.Equal(0, await _store.GetEntryCountAsync());

        await _store.AppendEntryAsync(CreateTestEntry("key1", "artifact1", "digest1", "sig1"));
        await _store.AppendEntryAsync(CreateTestEntry("key2", "artifact2", "digest2", "sig2"));
        await _store.AppendEntryAsync(CreateTestEntry("key3", "artifact3", "digest3", "sig3"));

        // Act
        var count = await _store.GetEntryCountAsync();

        // Assert
        Assert.Equal(3, count);
    }

    [Fact]
    public async Task GetLeafHashesAsync_ReturnsHashesInOrder()
    {
        // Arrange
        var entry1 = CreateTestEntry("key1", "artifact1", "digest1", "sig1");
        var entry2 = CreateTestEntry("key2", "artifact2", "digest2", "sig2");
        var entry3 = CreateTestEntry("key3", "artifact3", "digest3", "sig3");

        await _store.AppendEntryAsync(entry1);
        await _store.AppendEntryAsync(entry2);
        await _store.AppendEntryAsync(entry3);

        // Act
        var hashes = await _store.GetLeafHashesAsync();

        // Assert
        Assert.Equal(3, hashes.Count);
        Assert.Equal(entry1.LeafHash, hashes[0]);
        Assert.Equal(entry2.LeafHash, hashes[1]);
        Assert.Equal(entry3.LeafHash, hashes[2]);
    }

    [Fact]
    public async Task SaveCheckpointAsync_AndGetLatestCheckpointAsync_RoundTrip()
    {
        // Arrange
        var checkpoint = new LogStoreCheckpoint
        {
            TreeSize = 100,
            RootHash = "abc123def456",
            Timestamp = "2026-02-10T12:00:00Z",
            Signature = "base64signature"
        };

        // Act
        await _store.SaveCheckpointAsync(checkpoint);
        var retrieved = await _store.GetLatestCheckpointAsync();

        // Assert
        Assert.NotNull(retrieved);
        Assert.True(retrieved.Id > 0);
        Assert.Equal(100, retrieved.TreeSize);
        Assert.Equal("abc123def456", retrieved.RootHash);
        Assert.Equal("2026-02-10T12:00:00Z", retrieved.Timestamp);
        Assert.Equal("base64signature", retrieved.Signature);
    }

    [Fact]
    public async Task GetLatestCheckpointAsync_NoCheckpoints_ReturnsNull()
    {
        // Act
        var result = await _store.GetLatestCheckpointAsync();

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task GetLatestCheckpointAsync_MultipleCheckpoints_ReturnsNewest()
    {
        // Arrange
        await _store.SaveCheckpointAsync(new LogStoreCheckpoint
        {
            TreeSize = 10,
            RootHash = "old-hash",
            Timestamp = "2026-02-10T10:00:00Z",
            Signature = "old-sig"
        });

        await _store.SaveCheckpointAsync(new LogStoreCheckpoint
        {
            TreeSize = 20,
            RootHash = "new-hash",
            Timestamp = "2026-02-10T11:00:00Z",
            Signature = "new-sig"
        });

        // Act
        var latest = await _store.GetLatestCheckpointAsync();

        // Assert
        Assert.NotNull(latest);
        Assert.Equal(20, latest.TreeSize);
        Assert.Equal("new-hash", latest.RootHash);
    }

    [Fact]
    public async Task SignatureDigestExistsAsync_ExistingSignature_ReturnsTrue()
    {
        // Arrange
        await _store.AppendEntryAsync(CreateTestEntry("key1", "artifact1", "digest1", "unique-sig"));

        // Act
        var exists = await _store.SignatureDigestExistsAsync("unique-sig");

        // Assert
        Assert.True(exists);
    }

    [Fact]
    public async Task SignatureDigestExistsAsync_NonExistentSignature_ReturnsFalse()
    {
        // Act
        var exists = await _store.SignatureDigestExistsAsync("does-not-exist");

        // Assert
        Assert.False(exists);
    }

    private static LogStoreEntry CreateTestEntry(
        string keyId,
        string artifactName,
        string artifactDigest,
        string signatureDigest,
        string? label = null)
    {
        return new LogStoreEntry
        {
            Timestamp = DateTime.UtcNow.ToString("O"),
            KeyId = keyId,
            Algorithm = "ecdsa-p256",
            ArtifactName = artifactName,
            ArtifactDigest = artifactDigest,
            SignatureDigest = signatureDigest,
            Label = label,
            LeafHash = $"leaf-hash-{Guid.NewGuid():N}",
            RawJson = "{\"test\":\"data\"}"
        };
    }
}
