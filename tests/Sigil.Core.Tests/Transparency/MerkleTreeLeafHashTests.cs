using System.Security.Cryptography;
using System.Text;
using Sigil.Transparency;

namespace Sigil.Core.Tests.Transparency;

public class MerkleTreeLeafHashTests
{
    [Fact]
    public void LeafHash_prepends_0x00_prefix()
    {
        var data = "hello"u8.ToArray();
        var expected = SHA256.HashData([0x00, .. data]);

        var result = MerkleTree.ComputeLeafHash(data);

        Assert.Equal(expected, result);
    }

    [Fact]
    public void LeafHash_returns_32_bytes()
    {
        var result = MerkleTree.ComputeLeafHash("test"u8.ToArray());

        Assert.Equal(32, result.Length);
    }

    [Fact]
    public void LeafHash_is_deterministic()
    {
        var data = "deterministic"u8.ToArray();

        var result1 = MerkleTree.ComputeLeafHash(data);
        var result2 = MerkleTree.ComputeLeafHash(data);

        Assert.Equal(result1, result2);
    }

    [Fact]
    public void LeafHash_differs_for_different_inputs()
    {
        var hash1 = MerkleTree.ComputeLeafHash("alpha"u8.ToArray());
        var hash2 = MerkleTree.ComputeLeafHash("beta"u8.ToArray());

        Assert.NotEqual(hash1, hash2);
    }

    [Fact]
    public void LeafHash_differs_from_raw_SHA256()
    {
        var data = "no-prefix"u8.ToArray();

        var leafHash = MerkleTree.ComputeLeafHash(data);
        var rawHash = SHA256.HashData(data);

        Assert.NotEqual(leafHash, rawHash);
    }
}
