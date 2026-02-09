using System.Security.Cryptography;
using Sigil.Transparency;

namespace Sigil.Core.Tests.Transparency;

public class MerkleTreeNodeHashTests
{
    [Fact]
    public void NodeHash_prepends_0x01_prefix()
    {
        var left = SHA256.HashData("left"u8.ToArray());
        var right = SHA256.HashData("right"u8.ToArray());
        var expected = SHA256.HashData([0x01, .. left, .. right]);

        var result = MerkleTree.ComputeNodeHash(left, right);

        Assert.Equal(expected, result);
    }

    [Fact]
    public void NodeHash_returns_32_bytes()
    {
        var left = new byte[32];
        var right = new byte[32];

        var result = MerkleTree.ComputeNodeHash(left, right);

        Assert.Equal(32, result.Length);
    }

    [Fact]
    public void NodeHash_differs_from_leaf_hash()
    {
        var data = new byte[32];
        var leafHash = MerkleTree.ComputeLeafHash(data);
        var nodeHash = MerkleTree.ComputeNodeHash(data, data);

        Assert.NotEqual(leafHash, nodeHash);
    }

    [Fact]
    public void NodeHash_is_order_dependent()
    {
        var a = SHA256.HashData("a"u8.ToArray());
        var b = SHA256.HashData("b"u8.ToArray());

        var hash1 = MerkleTree.ComputeNodeHash(a, b);
        var hash2 = MerkleTree.ComputeNodeHash(b, a);

        Assert.NotEqual(hash1, hash2);
    }
}
