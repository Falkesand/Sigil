using System.Security.Cryptography;
using Sigil.Transparency;

namespace Sigil.Core.Tests.Transparency;

public class MerkleTreeRootTests
{
    [Fact]
    public void Root_of_empty_tree_is_hash_of_empty()
    {
        var expected = SHA256.HashData([]);

        var result = MerkleTree.ComputeRoot([]);

        Assert.Equal(expected, result);
    }

    [Fact]
    public void Root_of_single_leaf_is_the_leaf_hash()
    {
        var leaf = MerkleTree.ComputeLeafHash("only"u8.ToArray());

        var result = MerkleTree.ComputeRoot([leaf]);

        Assert.Equal(leaf, result);
    }

    [Fact]
    public void Root_of_two_leaves()
    {
        var a = MerkleTree.ComputeLeafHash("a"u8.ToArray());
        var b = MerkleTree.ComputeLeafHash("b"u8.ToArray());
        var expected = MerkleTree.ComputeNodeHash(a, b);

        var result = MerkleTree.ComputeRoot([a, b]);

        Assert.Equal(expected, result);
    }

    [Fact]
    public void Root_of_three_leaves()
    {
        var a = MerkleTree.ComputeLeafHash("a"u8.ToArray());
        var b = MerkleTree.ComputeLeafHash("b"u8.ToArray());
        var c = MerkleTree.ComputeLeafHash("c"u8.ToArray());
        // k=2: left=Node(a,b), right=c
        var expected = MerkleTree.ComputeNodeHash(
            MerkleTree.ComputeNodeHash(a, b), c);

        var result = MerkleTree.ComputeRoot([a, b, c]);

        Assert.Equal(expected, result);
    }

    [Fact]
    public void Root_of_four_leaves()
    {
        var a = MerkleTree.ComputeLeafHash("a"u8.ToArray());
        var b = MerkleTree.ComputeLeafHash("b"u8.ToArray());
        var c = MerkleTree.ComputeLeafHash("c"u8.ToArray());
        var d = MerkleTree.ComputeLeafHash("d"u8.ToArray());
        var expected = MerkleTree.ComputeNodeHash(
            MerkleTree.ComputeNodeHash(a, b),
            MerkleTree.ComputeNodeHash(c, d));

        var result = MerkleTree.ComputeRoot([a, b, c, d]);

        Assert.Equal(expected, result);
    }

    [Fact]
    public void Root_of_five_leaves()
    {
        var leaves = Enumerable.Range(0, 5)
            .Select(i => MerkleTree.ComputeLeafHash([(byte)i]))
            .ToList();
        // k=4: left=Root(0..3), right=Root(4)
        var leftSub = MerkleTree.ComputeNodeHash(
            MerkleTree.ComputeNodeHash(leaves[0], leaves[1]),
            MerkleTree.ComputeNodeHash(leaves[2], leaves[3]));
        var expected = MerkleTree.ComputeNodeHash(leftSub, leaves[4]);

        var result = MerkleTree.ComputeRoot(leaves);

        Assert.Equal(expected, result);
    }

    [Fact]
    public void Root_is_deterministic()
    {
        var leaves = Enumerable.Range(0, 8)
            .Select(i => MerkleTree.ComputeLeafHash([(byte)i]))
            .ToList();

        var root1 = MerkleTree.ComputeRoot(leaves);
        var root2 = MerkleTree.ComputeRoot(leaves);

        Assert.Equal(root1, root2);
    }

    [Fact]
    public void LargestPowerOf2LessThan_returns_correct_values()
    {
        Assert.Equal(1, MerkleTree.LargestPowerOf2LessThan(2));
        Assert.Equal(2, MerkleTree.LargestPowerOf2LessThan(3));
        Assert.Equal(4, MerkleTree.LargestPowerOf2LessThan(5));
        Assert.Equal(8, MerkleTree.LargestPowerOf2LessThan(9));
        Assert.Equal(8, MerkleTree.LargestPowerOf2LessThan(16));
        Assert.Equal(16, MerkleTree.LargestPowerOf2LessThan(17));
    }
}
