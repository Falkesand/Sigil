using System.Text.Json;
using Sigil.Trust;

namespace Sigil.Core.Tests.Trust;

public class RevocationEntrySerializationTests
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    [Fact]
    public void Round_trip_full_revocation_entry()
    {
        var entry = new RevocationEntry
        {
            Fingerprint = "sha256:abc123",
            RevokedAt = "2026-02-09T10:00:00Z",
            Reason = "Key compromised"
        };

        var json = JsonSerializer.Serialize(entry, JsonOptions);
        var deserialized = JsonSerializer.Deserialize<RevocationEntry>(json, JsonOptions);

        Assert.NotNull(deserialized);
        Assert.Equal("sha256:abc123", deserialized.Fingerprint);
        Assert.Equal("2026-02-09T10:00:00Z", deserialized.RevokedAt);
        Assert.Equal("Key compromised", deserialized.Reason);
    }

    [Fact]
    public void Round_trip_without_optional_reason()
    {
        var entry = new RevocationEntry
        {
            Fingerprint = "sha256:def456",
            RevokedAt = "2026-02-09T10:00:00Z"
        };

        var json = JsonSerializer.Serialize(entry, JsonOptions);
        var deserialized = JsonSerializer.Deserialize<RevocationEntry>(json, JsonOptions);

        Assert.NotNull(deserialized);
        Assert.Equal("sha256:def456", deserialized.Fingerprint);
        Assert.Null(deserialized.Reason);
        Assert.DoesNotContain("reason", json);
    }

    [Fact]
    public void Json_property_names_use_camelCase()
    {
        var entry = new RevocationEntry
        {
            Fingerprint = "sha256:abc123",
            RevokedAt = "2026-02-09T10:00:00Z",
            Reason = "test"
        };

        var json = JsonSerializer.Serialize(entry, JsonOptions);

        Assert.Contains("\"fingerprint\"", json);
        Assert.Contains("\"revokedAt\"", json);
        Assert.Contains("\"reason\"", json);
    }
}
