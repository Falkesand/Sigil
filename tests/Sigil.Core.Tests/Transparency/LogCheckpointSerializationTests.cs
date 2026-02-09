using System.Text.Json;
using Sigil.Transparency;

namespace Sigil.Core.Tests.Transparency;

public class LogCheckpointSerializationTests
{
    [Fact]
    public void Roundtrip_all_fields()
    {
        var checkpoint = new LogCheckpoint
        {
            TreeSize = 100,
            RootHash = "abcdef0123456789",
            Timestamp = "2026-01-15T12:00:00Z"
        };

        var json = JsonSerializer.Serialize(checkpoint);
        var deserialized = JsonSerializer.Deserialize<LogCheckpoint>(json)!;

        Assert.Equal(checkpoint.TreeSize, deserialized.TreeSize);
        Assert.Equal(checkpoint.RootHash, deserialized.RootHash);
        Assert.Equal(checkpoint.Timestamp, deserialized.Timestamp);
    }

    [Fact]
    public void Uses_correct_json_property_names()
    {
        var checkpoint = new LogCheckpoint
        {
            TreeSize = 5,
            RootHash = "aabb",
            Timestamp = "2026-01-15T12:00:00Z"
        };

        var json = JsonSerializer.Serialize(checkpoint);

        Assert.Contains("\"treeSize\":", json);
        Assert.Contains("\"rootHash\":", json);
        Assert.Contains("\"timestamp\":", json);
    }

    [Fact]
    public void Deserialize_from_json_string()
    {
        var json = """{"treeSize":10,"rootHash":"ff00ff00","timestamp":"2026-02-01T00:00:00Z"}""";

        var checkpoint = JsonSerializer.Deserialize<LogCheckpoint>(json)!;

        Assert.Equal(10, checkpoint.TreeSize);
        Assert.Equal("ff00ff00", checkpoint.RootHash);
    }
}
