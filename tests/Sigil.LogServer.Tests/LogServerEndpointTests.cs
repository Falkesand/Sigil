using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Xunit;

namespace Sigil.LogServer.Tests;

/// <summary>
/// Integration tests for all LogServer API endpoints.
/// Each test creates its own isolated server instance.
/// </summary>
public sealed class LogServerEndpointTests
{
    // Use PascalCase (default) to match server expectations
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = null
    };


    #region POST /api/v1/log/entries

    [Fact]
    public async Task PostEntries_ReturnsCreatedWithValidReceipt()
    {
        // Arrange
        await using var server = await TestLogServer.CreateAsync();
        var entry = CreateTestEntry();

        // Act
        var response = await server.Client.PostAsJsonAsync("/api/v1/log/entries", entry, JsonOptions);

        // Assert
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        var json = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.True(root.TryGetProperty("logIndex", out var logIndex));
        Assert.Equal(1, logIndex.GetInt64());

        Assert.True(root.TryGetProperty("leafHash", out var leafHash));
        Assert.False(string.IsNullOrWhiteSpace(leafHash.GetString()));

        Assert.True(root.TryGetProperty("signedCheckpoint", out var signedCheckpoint));
        Assert.False(string.IsNullOrWhiteSpace(signedCheckpoint.GetString()));

        Assert.True(root.TryGetProperty("inclusionProof", out var inclusionProof));
        Assert.True(inclusionProof.TryGetProperty("leafIndex", out var leafIndex));
        Assert.Equal(0, leafIndex.GetInt64()); // MerkleTree uses 0-based leaf indices
        Assert.True(inclusionProof.TryGetProperty("treeSize", out var treeSize));
        Assert.Equal(1, treeSize.GetInt64());
        Assert.True(inclusionProof.TryGetProperty("rootHash", out var rootHash));
        Assert.False(string.IsNullOrWhiteSpace(rootHash.GetString()));
        Assert.True(inclusionProof.TryGetProperty("hashes", out var hashes));
        Assert.Equal(JsonValueKind.Array, hashes.ValueKind);
    }

    [Fact]
    public async Task PostEntries_WithDuplicateSignature_ReturnsConflict()
    {
        // Arrange
        await using var server = await TestLogServer.CreateAsync();
        var entry = CreateTestEntry();
        await server.Client.PostAsJsonAsync("/api/v1/log/entries", entry, JsonOptions);

        // Act
        var response = await server.Client.PostAsJsonAsync("/api/v1/log/entries", entry, JsonOptions);

        // Assert
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
    }

    [Fact]
    public async Task PostEntries_WithMissingFields_ReturnsBadRequest()
    {
        // Arrange
        await using var server = await TestLogServer.CreateAsync();
        var entry = new { keyId = "test" }; // Missing required fields

        // Act
        var response = await server.Client.PostAsJsonAsync("/api/v1/log/entries", entry, JsonOptions);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task PostEntries_WithoutApiKey_ReturnsUnauthorized()
    {
        // Arrange
        await using var server = await TestLogServer.CreateAsync();
        var client = new HttpClient { BaseAddress = server.Client.BaseAddress };
        var entry = CreateTestEntry();

        // Act
        var response = await client.PostAsJsonAsync("/api/v1/log/entries", entry, JsonOptions);

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        client.Dispose();
    }

    [Fact]
    public async Task PostEntries_WithWrongApiKey_ReturnsUnauthorized()
    {
        // Arrange
        await using var server = await TestLogServer.CreateAsync();
        var client = new HttpClient { BaseAddress = server.Client.BaseAddress };
        client.DefaultRequestHeaders.Add("X-Api-Key", "wrong-key");
        var entry = CreateTestEntry();

        // Act
        var response = await client.PostAsJsonAsync("/api/v1/log/entries", entry, JsonOptions);

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        client.Dispose();
    }

    #endregion

    #region GET /api/v1/log/entries

    [Fact]
    public async Task GetEntries_ListsAllEntries()
    {
        // Arrange
        await using var server = await TestLogServer.CreateAsync();
        await server.Client.PostAsJsonAsync("/api/v1/log/entries", CreateTestEntry("key1"), JsonOptions);
        await server.Client.PostAsJsonAsync("/api/v1/log/entries", CreateTestEntry("key2"), JsonOptions);
        await server.Client.PostAsJsonAsync("/api/v1/log/entries", CreateTestEntry("key3"), JsonOptions);

        // Act
        var response = await server.Client.GetAsync("/api/v1/log/entries");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var json = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.True(root.TryGetProperty("total", out var total));
        Assert.Equal(3, total.GetInt32());

        Assert.True(root.TryGetProperty("entries", out var entries));
        Assert.Equal(3, entries.GetArrayLength());
    }

    [Fact]
    public async Task GetEntries_WithLimitAndOffset_PaginatesCorrectly()
    {
        // Arrange
        await using var server = await TestLogServer.CreateAsync();
        for (int i = 0; i < 5; i++)
        {
            await server.Client.PostAsJsonAsync("/api/v1/log/entries", CreateTestEntry($"key{i}"), JsonOptions);
        }

        // Act
        var response = await server.Client.GetAsync("/api/v1/log/entries?limit=2&offset=1");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var json = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.True(root.TryGetProperty("total", out var total));
        Assert.Equal(5, total.GetInt32());

        Assert.True(root.TryGetProperty("entries", out var entries));
        Assert.Equal(2, entries.GetArrayLength());
    }

    #endregion

    #region GET /api/v1/log/entries/{index}

    [Fact]
    public async Task GetEntriesByIndex_ReturnsCorrectEntry()
    {
        // Arrange
        await using var server = await TestLogServer.CreateAsync();
        var entry = CreateTestEntry("test-key-id");
        await server.Client.PostAsJsonAsync("/api/v1/log/entries", entry, JsonOptions);

        // Act
        var response = await server.Client.GetAsync("/api/v1/log/entries/1");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var json = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.True(root.TryGetProperty("keyId", out var keyId));
        Assert.Equal("test-key-id", keyId.GetString());
    }

    [Fact]
    public async Task GetEntriesByIndex_ForNonExistent_ReturnsNotFound()
    {
        // Arrange
        await using var server = await TestLogServer.CreateAsync();

        // Act
        var response = await server.Client.GetAsync("/api/v1/log/entries/999");

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    #endregion

    #region POST /api/v1/log/search

    [Fact]
    public async Task PostSearch_ByKeyId_ReturnsMatchingEntries()
    {
        // Arrange
        await using var server = await TestLogServer.CreateAsync();
        await server.Client.PostAsJsonAsync("/api/v1/log/entries", CreateTestEntry("target-key"), JsonOptions);
        await server.Client.PostAsJsonAsync("/api/v1/log/entries", CreateTestEntry("other-key"), JsonOptions);
        await server.Client.PostAsJsonAsync("/api/v1/log/entries", CreateTestEntry("target-key"), JsonOptions);

        // Act
        var searchRequest = new { KeyId = "target-key" };
        var response = await server.Client.PostAsJsonAsync("/api/v1/log/search", searchRequest, JsonOptions);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var json = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.True(root.TryGetProperty("entries", out var entries));
        Assert.Equal(2, entries.GetArrayLength());

        foreach (var entry in entries.EnumerateArray())
        {
            Assert.True(entry.TryGetProperty("keyId", out var keyId));
            Assert.Equal("target-key", keyId.GetString());
        }
    }

    [Fact]
    public async Task PostSearch_ByArtifactName_ReturnsMatchingEntries()
    {
        // Arrange
        await using var server = await TestLogServer.CreateAsync();
        await server.Client.PostAsJsonAsync("/api/v1/log/entries", CreateTestEntry("key1", "artifact-a"), JsonOptions);
        await server.Client.PostAsJsonAsync("/api/v1/log/entries", CreateTestEntry("key2", "artifact-b"), JsonOptions);
        await server.Client.PostAsJsonAsync("/api/v1/log/entries", CreateTestEntry("key3", "artifact-a"), JsonOptions);

        // Act
        var searchRequest = new { ArtifactName = "artifact-a" };
        var response = await server.Client.PostAsJsonAsync("/api/v1/log/search", searchRequest, JsonOptions);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var json = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.True(root.TryGetProperty("entries", out var entries));
        Assert.Equal(2, entries.GetArrayLength());

        foreach (var entry in entries.EnumerateArray())
        {
            Assert.True(entry.TryGetProperty("artifactName", out var artifactName));
            Assert.Equal("artifact-a", artifactName.GetString());
        }
    }

    [Fact]
    public async Task PostSearch_ByArtifactDigest_ReturnsMatchingEntries()
    {
        // Arrange
        await using var server = await TestLogServer.CreateAsync();
        var digest1 = Convert.ToBase64String(SHA256.HashData("data1"u8.ToArray()));
        var digest2 = Convert.ToBase64String(SHA256.HashData("data2"u8.ToArray()));

        await server.Client.PostAsJsonAsync("/api/v1/log/entries", CreateTestEntry("key1", "artifact1", digest1), JsonOptions);
        await server.Client.PostAsJsonAsync("/api/v1/log/entries", CreateTestEntry("key2", "artifact2", digest2), JsonOptions);
        await server.Client.PostAsJsonAsync("/api/v1/log/entries", CreateTestEntry("key3", "artifact3", digest1), JsonOptions);

        // Act
        var searchRequest = new { ArtifactDigest = digest1 };
        var response = await server.Client.PostAsJsonAsync("/api/v1/log/search", searchRequest, JsonOptions);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var json = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.True(root.TryGetProperty("entries", out var entries));
        Assert.Equal(2, entries.GetArrayLength());

        foreach (var entry in entries.EnumerateArray())
        {
            Assert.True(entry.TryGetProperty("artifactDigest", out var artifactDigest));
            Assert.Equal(digest1, artifactDigest.GetString());
        }
    }

    #endregion

    #region GET /api/v1/log/checkpoint

    [Fact]
    public async Task GetCheckpoint_ReturnsEmptyCheckpointInitially()
    {
        // Arrange
        await using var server = await TestLogServer.CreateAsync();

        // Act
        var response = await server.Client.GetAsync("/api/v1/log/checkpoint");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var json = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.True(root.TryGetProperty("treeSize", out var treeSize));
        Assert.Equal(0, treeSize.GetInt64());

        Assert.True(root.TryGetProperty("rootHash", out var rootHash));
        Assert.False(string.IsNullOrWhiteSpace(rootHash.GetString()));

        Assert.True(root.TryGetProperty("timestamp", out var timestamp));
        Assert.False(string.IsNullOrWhiteSpace(timestamp.GetString()));

        Assert.True(root.TryGetProperty("signature", out var signature));
        Assert.Equal("", signature.GetString()); // Empty signature for initial checkpoint
    }

    [Fact]
    public async Task GetCheckpoint_ReturnsSignedCheckpointAfterAppend()
    {
        // Arrange
        await using var server = await TestLogServer.CreateAsync();
        await server.Client.PostAsJsonAsync("/api/v1/log/entries", CreateTestEntry(), JsonOptions);

        // Act
        var response = await server.Client.GetAsync("/api/v1/log/checkpoint");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var json = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.True(root.TryGetProperty("treeSize", out var treeSize));
        Assert.Equal(1, treeSize.GetInt64());

        Assert.True(root.TryGetProperty("rootHash", out var rootHash));
        Assert.False(string.IsNullOrWhiteSpace(rootHash.GetString()));

        Assert.True(root.TryGetProperty("timestamp", out var timestamp));
        Assert.False(string.IsNullOrWhiteSpace(timestamp.GetString()));

        Assert.True(root.TryGetProperty("signature", out var signature));
        Assert.False(string.IsNullOrWhiteSpace(signature.GetString()));
    }

    #endregion

    #region GET /api/v1/log/proof/inclusion/{index}

    [Fact]
    public async Task GetProofInclusion_ReturnsValidProof()
    {
        // Arrange
        await using var server = await TestLogServer.CreateAsync();
        await server.Client.PostAsJsonAsync("/api/v1/log/entries", CreateTestEntry(), JsonOptions);
        await server.Client.PostAsJsonAsync("/api/v1/log/entries", CreateTestEntry(), JsonOptions);

        // Act
        var response = await server.Client.GetAsync("/api/v1/log/proof/inclusion/1");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var json = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.True(root.TryGetProperty("leafIndex", out var leafIndex));
        Assert.Equal(1, leafIndex.GetInt64()); // Database ID 1 is used directly as Merkle index

        Assert.True(root.TryGetProperty("treeSize", out var treeSize));
        Assert.Equal(2, treeSize.GetInt64());

        Assert.True(root.TryGetProperty("rootHash", out var rootHash));
        Assert.False(string.IsNullOrWhiteSpace(rootHash.GetString()));

        Assert.True(root.TryGetProperty("hashes", out var hashes));
        Assert.Equal(JsonValueKind.Array, hashes.ValueKind);
    }

    [Fact]
    public async Task GetProofInclusion_ForInvalidIndex_ReturnsNotFound()
    {
        // Arrange
        await using var server = await TestLogServer.CreateAsync();

        // Act
        var response = await server.Client.GetAsync("/api/v1/log/proof/inclusion/999");

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    #endregion

    #region GET /api/v1/log/proof/consistency

    [Fact]
    public async Task GetProofConsistency_BetweenOldAndNewTreeSizes()
    {
        // Arrange
        await using var server = await TestLogServer.CreateAsync();
        await server.Client.PostAsJsonAsync("/api/v1/log/entries", CreateTestEntry(), JsonOptions);
        await server.Client.PostAsJsonAsync("/api/v1/log/entries", CreateTestEntry(), JsonOptions);
        await server.Client.PostAsJsonAsync("/api/v1/log/entries", CreateTestEntry(), JsonOptions);

        // Act
        var response = await server.Client.GetAsync("/api/v1/log/proof/consistency?oldSize=1");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var json = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.True(root.TryGetProperty("oldSize", out var oldSize));
        Assert.Equal(1, oldSize.GetInt64());

        Assert.True(root.TryGetProperty("newSize", out var newSize));
        Assert.Equal(3, newSize.GetInt64());

        Assert.True(root.TryGetProperty("oldRootHash", out var oldRootHash));
        Assert.False(string.IsNullOrWhiteSpace(oldRootHash.GetString()));

        Assert.True(root.TryGetProperty("newRootHash", out var newRootHash));
        Assert.False(string.IsNullOrWhiteSpace(newRootHash.GetString()));

        Assert.True(root.TryGetProperty("hashes", out var hashes));
        Assert.Equal(JsonValueKind.Array, hashes.ValueKind);
    }

    #endregion

    #region GET /api/v1/log/publicKey

    [Fact]
    public async Task GetPublicKey_ReturnsBase64EncodedSpki()
    {
        // Arrange
        await using var server = await TestLogServer.CreateAsync();

        // Act
        var response = await server.Client.GetAsync("/api/v1/log/publicKey");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("text/plain", response.Content.Headers.ContentType?.MediaType);

        var publicKey = await response.Content.ReadAsStringAsync();
        Assert.False(string.IsNullOrWhiteSpace(publicKey));

        // Should match the server's public key
        Assert.Equal(server.Signer.PublicKeyBase64, publicKey.Trim());
    }

    #endregion

    #region Multi-Entry Tests

    [Fact]
    public async Task MultipleAppends_ProduceIncreasingLogIndices()
    {
        // Arrange
        await using var server = await TestLogServer.CreateAsync();

        // Act
        var response1 = await server.Client.PostAsJsonAsync("/api/v1/log/entries", CreateTestEntry(), JsonOptions);
        var response2 = await server.Client.PostAsJsonAsync("/api/v1/log/entries", CreateTestEntry(), JsonOptions);
        var response3 = await server.Client.PostAsJsonAsync("/api/v1/log/entries", CreateTestEntry(), JsonOptions);

        // Assert
        var json1 = await response1.Content.ReadAsStringAsync();
        var json2 = await response2.Content.ReadAsStringAsync();
        var json3 = await response3.Content.ReadAsStringAsync();

        using var doc1 = JsonDocument.Parse(json1);
        using var doc2 = JsonDocument.Parse(json2);
        using var doc3 = JsonDocument.Parse(json3);

        var index1 = doc1.RootElement.GetProperty("logIndex").GetInt64();
        var index2 = doc2.RootElement.GetProperty("logIndex").GetInt64();
        var index3 = doc3.RootElement.GetProperty("logIndex").GetInt64();

        Assert.Equal(1, index1);
        Assert.Equal(2, index2);
        Assert.Equal(3, index3);
    }

    [Fact]
    public async Task CheckpointSignature_IsVerifiableWithServerPublicKey()
    {
        // Arrange
        await using var server = await TestLogServer.CreateAsync();
        await server.Client.PostAsJsonAsync("/api/v1/log/entries", CreateTestEntry(), JsonOptions);

        // Act
        var response = await server.Client.GetAsync("/api/v1/log/checkpoint");
        var json = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        var treeSize = root.GetProperty("treeSize").GetInt64();
        var rootHash = root.GetProperty("rootHash").GetString()!;
        var timestamp = root.GetProperty("timestamp").GetString()!;
        var signatureBase64 = root.GetProperty("signature").GetString()!;

        // Decode the checkpoint signature format: base64(json_payload.base64_signature)
        var decoded = Convert.FromBase64String(signatureBase64);
        var combined = Encoding.UTF8.GetString(decoded);
        var lastDotIndex = combined.LastIndexOf('.');
        Assert.True(lastDotIndex > 0, "Expected checkpoint to contain payload.signature separator");

        var payloadJson = combined[..lastDotIndex];
        var signatureBytes = Convert.FromBase64String(combined[(lastDotIndex + 1)..]);

        // Verify the signature
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportSubjectPublicKeyInfo(server.Signer.PublicKeySpki, out _);

        var payloadBytes = Encoding.UTF8.GetBytes(payloadJson);
        var isValid = ecdsa.VerifyData(payloadBytes, signatureBytes, HashAlgorithmName.SHA256);

        Assert.True(isValid, "Checkpoint signature should be verifiable with server's public key");
    }

    #endregion

    #region Helper Methods

    private static object CreateTestEntry(string keyId = "test-key", string artifactName = "test-artifact", string? artifactDigest = null)
    {
        var sigBytes = new byte[64];
        Random.Shared.NextBytes(sigBytes);
        var signatureValue = Convert.ToBase64String(sigBytes);

        var pubKeyBytes = new byte[91]; // Typical ECDSA P-256 SPKI length
        Random.Shared.NextBytes(pubKeyBytes);
        var publicKey = Convert.ToBase64String(pubKeyBytes);

        artifactDigest ??= Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(artifactName)));

        return new
        {
            KeyId = keyId,
            Algorithm = "ecdsa-p256",
            PublicKey = publicKey,
            SignatureValue = signatureValue,
            ArtifactName = artifactName,
            ArtifactDigest = artifactDigest,
            Label = "test-label"
        };
    }

    #endregion
}
