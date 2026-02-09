using System.Text.Json;
using Sigil.Transparency;

namespace Sigil.Core.Tests.Transparency;

public class ConsistencyProofSerializationTests
{
    [Fact]
    public void Roundtrip_all_fields()
    {
        var proof = new ConsistencyProof
        {
            OldSize = 4,
            NewSize = 8,
            OldRootHash = "oldroot",
            NewRootHash = "newroot",
            Hashes = ["hash1", "hash2"]
        };

        var json = JsonSerializer.Serialize(proof);
        var deserialized = JsonSerializer.Deserialize<ConsistencyProof>(json)!;

        Assert.Equal(proof.OldSize, deserialized.OldSize);
        Assert.Equal(proof.NewSize, deserialized.NewSize);
        Assert.Equal(proof.OldRootHash, deserialized.OldRootHash);
        Assert.Equal(proof.NewRootHash, deserialized.NewRootHash);
        Assert.Equal(proof.Hashes, deserialized.Hashes);
    }

    [Fact]
    public void Uses_correct_json_property_names()
    {
        var proof = new ConsistencyProof
        {
            OldSize = 1,
            NewSize = 2,
            OldRootHash = "aa",
            NewRootHash = "bb",
            Hashes = ["cc"]
        };

        var json = JsonSerializer.Serialize(proof);

        Assert.Contains("\"oldSize\":", json);
        Assert.Contains("\"newSize\":", json);
        Assert.Contains("\"oldRootHash\":", json);
        Assert.Contains("\"newRootHash\":", json);
        Assert.Contains("\"hashes\":", json);
    }

    [Fact]
    public void Empty_hashes_serializes_as_empty_array()
    {
        var proof = new ConsistencyProof
        {
            OldSize = 4,
            NewSize = 4,
            OldRootHash = "same",
            NewRootHash = "same",
            Hashes = []
        };

        var json = JsonSerializer.Serialize(proof);

        Assert.Contains("\"hashes\":[]", json);
    }
}
