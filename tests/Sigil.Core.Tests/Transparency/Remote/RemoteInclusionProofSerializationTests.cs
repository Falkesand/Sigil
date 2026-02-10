using System.Text.Json;
using Sigil.Transparency.Remote;

namespace Sigil.Core.Tests.Transparency.Remote;

public class RemoteInclusionProofSerializationTests
{
    [Fact]
    public void Roundtrip_all_fields()
    {
        var proof = new RemoteInclusionProof
        {
            LeafIndex = 42,
            TreeSize = 100,
            RootHash = "aabbccdd",
            Hashes = ["1111", "2222", "3333"]
        };

        var json = JsonSerializer.Serialize(proof);
        var deserialized = JsonSerializer.Deserialize<RemoteInclusionProof>(json)!;

        Assert.Equal(proof.LeafIndex, deserialized.LeafIndex);
        Assert.Equal(proof.TreeSize, deserialized.TreeSize);
        Assert.Equal(proof.RootHash, deserialized.RootHash);
        Assert.Equal(proof.Hashes, deserialized.Hashes);
    }

    [Fact]
    public void Uses_correct_json_property_names()
    {
        var proof = new RemoteInclusionProof
        {
            LeafIndex = 0,
            TreeSize = 1,
            RootHash = "aa",
            Hashes = []
        };

        var json = JsonSerializer.Serialize(proof);

        Assert.Contains("\"leafIndex\":", json);
        Assert.Contains("\"treeSize\":", json);
        Assert.Contains("\"rootHash\":", json);
        Assert.Contains("\"hashes\":", json);
    }

    [Fact]
    public void Empty_hashes_serializes_as_empty_array()
    {
        var proof = new RemoteInclusionProof
        {
            LeafIndex = 0,
            TreeSize = 1,
            RootHash = "aa",
            Hashes = []
        };

        var json = JsonSerializer.Serialize(proof);

        Assert.Contains("\"hashes\":[]", json);
    }
}
