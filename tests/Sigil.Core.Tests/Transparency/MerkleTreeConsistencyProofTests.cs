using Sigil.Transparency;

namespace Sigil.Core.Tests.Transparency;

public class MerkleTreeConsistencyProofTests
{
    private static List<byte[]> MakeLeaves(int count) =>
        Enumerable.Range(0, count)
            .Select(i => MerkleTree.ComputeLeafHash([(byte)i]))
            .ToList();

    [Fact]
    public void Same_size_tree_has_empty_proof()
    {
        var leaves = MakeLeaves(4);
        var proof = MerkleTree.GenerateConsistencyProof(4, leaves);

        Assert.Equal(4, proof.OldSize);
        Assert.Equal(4, proof.NewSize);
        Assert.Empty(proof.Hashes);
        Assert.Equal(proof.OldRootHash, proof.NewRootHash);
        Assert.True(MerkleTree.VerifyConsistencyProof(proof));
    }

    [Fact]
    public void Grow_from_1_to_2()
    {
        var leaves = MakeLeaves(2);
        var proof = MerkleTree.GenerateConsistencyProof(1, leaves);

        Assert.True(proof.Hashes.Count > 0);
        Assert.True(MerkleTree.VerifyConsistencyProof(proof));
    }

    [Fact]
    public void Grow_from_2_to_4()
    {
        var leaves = MakeLeaves(4);
        var proof = MerkleTree.GenerateConsistencyProof(2, leaves);

        Assert.True(MerkleTree.VerifyConsistencyProof(proof));
    }

    [Fact]
    public void Grow_from_3_to_7()
    {
        var leaves = MakeLeaves(7);
        var proof = MerkleTree.GenerateConsistencyProof(3, leaves);

        Assert.True(MerkleTree.VerifyConsistencyProof(proof));
    }

    [Fact]
    public void Grow_from_4_to_8()
    {
        var leaves = MakeLeaves(8);
        var proof = MerkleTree.GenerateConsistencyProof(4, leaves);

        Assert.True(MerkleTree.VerifyConsistencyProof(proof));
    }

    [Fact]
    public void Grow_from_1_to_8()
    {
        var leaves = MakeLeaves(8);
        var proof = MerkleTree.GenerateConsistencyProof(1, leaves);

        Assert.True(MerkleTree.VerifyConsistencyProof(proof));
    }

    [Fact]
    public void Tampered_old_root_fails_verification()
    {
        var leaves = MakeLeaves(4);
        var proof = MerkleTree.GenerateConsistencyProof(2, leaves);

        var tampered = new ConsistencyProof
        {
            OldSize = proof.OldSize,
            NewSize = proof.NewSize,
            OldRootHash = "0000000000000000000000000000000000000000000000000000000000000000",
            NewRootHash = proof.NewRootHash,
            Hashes = proof.Hashes
        };

        Assert.False(MerkleTree.VerifyConsistencyProof(tampered));
    }
}
