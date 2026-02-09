using Sigil.Transparency;

namespace Sigil.Core.Tests.Transparency;

public class MerkleTreeInclusionProofTests
{
    private static List<byte[]> MakeLeaves(int count) =>
        Enumerable.Range(0, count)
            .Select(i => MerkleTree.ComputeLeafHash([(byte)i]))
            .ToList();

    [Fact]
    public void Proof_for_single_leaf_tree_has_empty_path()
    {
        var leaves = MakeLeaves(1);

        var proof = MerkleTree.GenerateInclusionProof(0, leaves);

        Assert.Equal(0, proof.LeafIndex);
        Assert.Equal(1, proof.TreeSize);
        Assert.Empty(proof.Hashes);
    }

    [Fact]
    public void Proof_for_two_leaf_tree_index_0()
    {
        var leaves = MakeLeaves(2);

        var proof = MerkleTree.GenerateInclusionProof(0, leaves);

        Assert.Single(proof.Hashes);
        Assert.True(MerkleTree.VerifyInclusionProof(proof, leaves[0]));
    }

    [Fact]
    public void Proof_for_two_leaf_tree_index_1()
    {
        var leaves = MakeLeaves(2);

        var proof = MerkleTree.GenerateInclusionProof(1, leaves);

        Assert.Single(proof.Hashes);
        Assert.True(MerkleTree.VerifyInclusionProof(proof, leaves[1]));
    }

    [Fact]
    public void Proof_for_four_leaf_tree_all_indices()
    {
        var leaves = MakeLeaves(4);

        for (int i = 0; i < 4; i++)
        {
            var proof = MerkleTree.GenerateInclusionProof(i, leaves);
            Assert.Equal(2, proof.Hashes.Count);
            Assert.True(MerkleTree.VerifyInclusionProof(proof, leaves[i]));
        }
    }

    [Fact]
    public void Proof_for_seven_leaf_tree()
    {
        var leaves = MakeLeaves(7);

        for (int i = 0; i < 7; i++)
        {
            var proof = MerkleTree.GenerateInclusionProof(i, leaves);
            Assert.True(MerkleTree.VerifyInclusionProof(proof, leaves[i]));
        }
    }

    [Fact]
    public void Proof_for_sixteen_leaf_tree()
    {
        var leaves = MakeLeaves(16);

        for (int i = 0; i < 16; i++)
        {
            var proof = MerkleTree.GenerateInclusionProof(i, leaves);
            Assert.Equal(4, proof.Hashes.Count);
            Assert.True(MerkleTree.VerifyInclusionProof(proof, leaves[i]));
        }
    }

    [Fact]
    public void Proof_fails_for_wrong_leaf()
    {
        var leaves = MakeLeaves(4);
        var proof = MerkleTree.GenerateInclusionProof(0, leaves);

        var wrongLeaf = MerkleTree.ComputeLeafHash("wrong"u8.ToArray());

        Assert.False(MerkleTree.VerifyInclusionProof(proof, wrongLeaf));
    }

    [Fact]
    public void Proof_root_hash_matches_computed_root()
    {
        var leaves = MakeLeaves(5);
        var expectedRoot = Convert.ToHexStringLower(MerkleTree.ComputeRoot(leaves));

        var proof = MerkleTree.GenerateInclusionProof(2, leaves);

        Assert.Equal(expectedRoot, proof.RootHash);
    }
}
