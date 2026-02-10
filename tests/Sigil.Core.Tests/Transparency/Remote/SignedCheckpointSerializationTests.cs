using System.Text.Json;
using Sigil.Transparency.Remote;

namespace Sigil.Core.Tests.Transparency.Remote;

public class SignedCheckpointSerializationTests
{
    [Fact]
    public void Roundtrip_all_fields()
    {
        var checkpoint = new SignedCheckpoint
        {
            TreeSize = 100,
            RootHash = "aabbccdd",
            Timestamp = "2026-02-10T12:00:00Z",
            Signature = "dGVzdA=="
        };

        var json = JsonSerializer.Serialize(checkpoint);
        var deserialized = JsonSerializer.Deserialize<SignedCheckpoint>(json)!;

        Assert.Equal(checkpoint.TreeSize, deserialized.TreeSize);
        Assert.Equal(checkpoint.RootHash, deserialized.RootHash);
        Assert.Equal(checkpoint.Timestamp, deserialized.Timestamp);
        Assert.Equal(checkpoint.Signature, deserialized.Signature);
    }

    [Fact]
    public void Uses_correct_json_property_names()
    {
        var checkpoint = new SignedCheckpoint
        {
            TreeSize = 1,
            RootHash = "aa",
            Timestamp = "2026-01-01T00:00:00Z",
            Signature = "c2ln"
        };

        var json = JsonSerializer.Serialize(checkpoint);

        Assert.Contains("\"treeSize\":", json);
        Assert.Contains("\"rootHash\":", json);
        Assert.Contains("\"timestamp\":", json);
        Assert.Contains("\"signature\":", json);
    }
}
