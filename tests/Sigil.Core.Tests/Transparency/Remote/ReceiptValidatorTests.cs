using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Org.Webpki.JsonCanonicalizer;
using Sigil.Transparency;
using Sigil.Transparency.Remote;

namespace Sigil.Core.Tests.Transparency.Remote;

public class ReceiptValidatorTests
{
    [Fact]
    public void ValidateInclusionProof_valid_proof_succeeds()
    {
        // Build a real Merkle tree with known data
        var leaves = new List<byte[]>();
        for (int i = 0; i < 4; i++)
        {
            leaves.Add(MerkleTree.ComputeLeafHash(Encoding.UTF8.GetBytes($"entry-{i}")));
        }

        var proof = MerkleTree.GenerateInclusionProof(2, leaves);
        var leafHash = Convert.ToHexStringLower(leaves[2]);

        var remoteProof = new RemoteInclusionProof
        {
            LeafIndex = proof.LeafIndex,
            TreeSize = proof.TreeSize,
            RootHash = proof.RootHash,
            Hashes = proof.Hashes.ToList()
        };

        var result = ReceiptValidator.ValidateInclusionProof(remoteProof, leafHash);

        Assert.True(result.IsSuccess);
        Assert.True(result.Value);
    }

    [Fact]
    public void ValidateInclusionProof_invalid_leaf_hash_fails()
    {
        var leaves = new List<byte[]>();
        for (int i = 0; i < 4; i++)
        {
            leaves.Add(MerkleTree.ComputeLeafHash(Encoding.UTF8.GetBytes($"entry-{i}")));
        }

        var proof = MerkleTree.GenerateInclusionProof(2, leaves);
        var wrongLeafHash = Convert.ToHexStringLower(leaves[0]); // Wrong leaf

        var remoteProof = new RemoteInclusionProof
        {
            LeafIndex = proof.LeafIndex,
            TreeSize = proof.TreeSize,
            RootHash = proof.RootHash,
            Hashes = proof.Hashes.ToList()
        };

        var result = ReceiptValidator.ValidateInclusionProof(remoteProof, wrongLeafHash);

        Assert.False(result.IsSuccess);
        Assert.Equal(RemoteLogErrorKind.InvalidProof, result.ErrorKind);
    }

    [Fact]
    public void ValidateInclusionProof_invalid_hex_fails()
    {
        var remoteProof = new RemoteInclusionProof
        {
            LeafIndex = 0,
            TreeSize = 1,
            RootHash = "aa",
            Hashes = []
        };

        var result = ReceiptValidator.ValidateInclusionProof(remoteProof, "not-valid-hex!");

        Assert.False(result.IsSuccess);
        Assert.Equal(RemoteLogErrorKind.InvalidProof, result.ErrorKind);
    }

    [Fact]
    public void ValidateSignedCheckpoint_valid_signature_succeeds()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = ecdsa.ExportSubjectPublicKeyInfo();

        var payload = JsonSerializer.Serialize(new { treeSize = 10, rootHash = "aabb", timestamp = "2026-01-01T00:00:00Z" });
        var canonical = new JsonCanonicalizer(payload).GetEncodedUTF8();
        var signature = ecdsa.SignData(canonical, HashAlgorithmName.SHA256);

        var checkpoint = payload + "." + Convert.ToBase64String(signature);
        var checkpointBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(checkpoint));

        var result = ReceiptValidator.ValidateSignedCheckpoint(checkpointBase64, publicKey);

        Assert.True(result.IsSuccess);
        Assert.True(result.Value);
    }

    [Fact]
    public void ValidateSignedCheckpoint_wrong_key_fails()
    {
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var wrongKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var wrongPublicKey = wrongKey.ExportSubjectPublicKeyInfo();

        var payload = JsonSerializer.Serialize(new { treeSize = 10, rootHash = "aabb" });
        var canonical = new JsonCanonicalizer(payload).GetEncodedUTF8();
        var signature = signingKey.SignData(canonical, HashAlgorithmName.SHA256);

        var checkpoint = payload + "." + Convert.ToBase64String(signature);
        var checkpointBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(checkpoint));

        var result = ReceiptValidator.ValidateSignedCheckpoint(checkpointBase64, wrongPublicKey);

        Assert.False(result.IsSuccess);
        Assert.Equal(RemoteLogErrorKind.InvalidCheckpoint, result.ErrorKind);
    }

    [Fact]
    public void ValidateSignedCheckpoint_invalid_base64_fails()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = ecdsa.ExportSubjectPublicKeyInfo();

        var result = ReceiptValidator.ValidateSignedCheckpoint("not-valid-base64!!!", publicKey);

        Assert.False(result.IsSuccess);
        Assert.Equal(RemoteLogErrorKind.InvalidCheckpoint, result.ErrorKind);
    }

    [Fact]
    public void ValidateSignedCheckpoint_missing_separator_fails()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = ecdsa.ExportSubjectPublicKeyInfo();

        var noSeparator = Convert.ToBase64String(Encoding.UTF8.GetBytes("no-separator-here"));

        var result = ReceiptValidator.ValidateSignedCheckpoint(noSeparator, publicKey);

        Assert.False(result.IsSuccess);
        Assert.Equal(RemoteLogErrorKind.InvalidCheckpoint, result.ErrorKind);
    }

    [Fact]
    public void ValidateReceipt_valid_receipt_no_key_succeeds()
    {
        var leaves = new List<byte[]>();
        for (int i = 0; i < 4; i++)
        {
            leaves.Add(MerkleTree.ComputeLeafHash(Encoding.UTF8.GetBytes($"entry-{i}")));
        }

        var proof = MerkleTree.GenerateInclusionProof(1, leaves);
        var leafHash = Convert.ToHexStringLower(leaves[1]);

        var receipt = new TransparencyReceipt
        {
            LogUrl = "https://log.example.com",
            LogIndex = 1,
            SignedCheckpoint = "dGVzdA==",
            InclusionProof = new RemoteInclusionProof
            {
                LeafIndex = proof.LeafIndex,
                TreeSize = proof.TreeSize,
                RootHash = proof.RootHash,
                Hashes = proof.Hashes.ToList()
            }
        };

        var result = ReceiptValidator.ValidateReceipt(receipt, leafHash);

        Assert.True(result.IsSuccess);
    }

    [Fact]
    public void ValidateReceipt_valid_receipt_with_key_succeeds()
    {
        var leaves = new List<byte[]>();
        for (int i = 0; i < 4; i++)
        {
            leaves.Add(MerkleTree.ComputeLeafHash(Encoding.UTF8.GetBytes($"entry-{i}")));
        }

        var proof = MerkleTree.GenerateInclusionProof(0, leaves);
        var leafHash = Convert.ToHexStringLower(leaves[0]);

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = ecdsa.ExportSubjectPublicKeyInfo();

        var payload = JsonSerializer.Serialize(new { treeSize = 4, rootHash = proof.RootHash });
        var canonical = new JsonCanonicalizer(payload).GetEncodedUTF8();
        var signature = ecdsa.SignData(canonical, HashAlgorithmName.SHA256);

        var checkpoint = payload + "." + Convert.ToBase64String(signature);
        var checkpointBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(checkpoint));

        var receipt = new TransparencyReceipt
        {
            LogUrl = "https://log.example.com",
            LogIndex = 0,
            SignedCheckpoint = checkpointBase64,
            InclusionProof = new RemoteInclusionProof
            {
                LeafIndex = proof.LeafIndex,
                TreeSize = proof.TreeSize,
                RootHash = proof.RootHash,
                Hashes = proof.Hashes.ToList()
            }
        };

        var result = ReceiptValidator.ValidateReceipt(receipt, leafHash, publicKey);

        Assert.True(result.IsSuccess);
    }

    [Fact]
    public void ValidateReceipt_invalid_proof_fails_even_with_valid_key()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = ecdsa.ExportSubjectPublicKeyInfo();

        var receipt = new TransparencyReceipt
        {
            LogUrl = "https://log.example.com",
            LogIndex = 0,
            SignedCheckpoint = "dGVzdA==",
            InclusionProof = new RemoteInclusionProof
            {
                LeafIndex = 0,
                TreeSize = 4,
                RootHash = "aabbccdd",
                Hashes = ["1111", "2222"]
            }
        };

        // Use a leaf hash that doesn't match the proof
        var result = ReceiptValidator.ValidateReceipt(
            receipt, "0000000000000000000000000000000000000000000000000000000000000000", publicKey);

        Assert.False(result.IsSuccess);
        Assert.Equal(RemoteLogErrorKind.InvalidProof, result.ErrorKind);
    }

    [Fact]
    public void ValidateInclusionProof_null_proof_throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            ReceiptValidator.ValidateInclusionProof(null!, "aabb"));
    }

    [Fact]
    public void ValidateInclusionProof_null_leaf_hash_throws()
    {
        var proof = new RemoteInclusionProof
        {
            LeafIndex = 0,
            TreeSize = 1,
            RootHash = "aa",
            Hashes = []
        };

        Assert.Throws<ArgumentNullException>(() =>
            ReceiptValidator.ValidateInclusionProof(proof, null!));
    }

    [Fact]
    public void ValidateReceipt_null_receipt_throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            ReceiptValidator.ValidateReceipt(null!, "aabb"));
    }
}
