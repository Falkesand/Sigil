using System.Text.Json;
using Sigil.Transparency.Remote;

namespace Sigil.Core.Tests.Transparency.Remote;

public class TransparencyReceiptSerializationTests
{
    [Fact]
    public void Roundtrip_all_fields()
    {
        var receipt = new TransparencyReceipt
        {
            LogUrl = "https://log.example.com",
            LogIndex = 42,
            SignedCheckpoint = "dGVzdA==",
            InclusionProof = new RemoteInclusionProof
            {
                LeafIndex = 42,
                TreeSize = 100,
                RootHash = "aabbccdd",
                Hashes = ["1111", "2222"]
            }
        };

        var json = JsonSerializer.Serialize(receipt);
        var deserialized = JsonSerializer.Deserialize<TransparencyReceipt>(json)!;

        Assert.Equal(receipt.LogUrl, deserialized.LogUrl);
        Assert.Equal(receipt.LogIndex, deserialized.LogIndex);
        Assert.Equal(receipt.SignedCheckpoint, deserialized.SignedCheckpoint);
        Assert.Equal(receipt.InclusionProof.LeafIndex, deserialized.InclusionProof.LeafIndex);
        Assert.Equal(receipt.InclusionProof.TreeSize, deserialized.InclusionProof.TreeSize);
    }

    [Fact]
    public void Uses_correct_json_property_names()
    {
        var receipt = new TransparencyReceipt
        {
            LogUrl = "https://log.example.com",
            LogIndex = 1,
            SignedCheckpoint = "dGVzdA==",
            InclusionProof = new RemoteInclusionProof
            {
                LeafIndex = 1,
                TreeSize = 1,
                RootHash = "aa",
                Hashes = []
            }
        };

        var json = JsonSerializer.Serialize(receipt);

        Assert.Contains("\"logUrl\":", json);
        Assert.Contains("\"logIndex\":", json);
        Assert.Contains("\"signedCheckpoint\":", json);
        Assert.Contains("\"inclusionProof\":", json);
    }
}
