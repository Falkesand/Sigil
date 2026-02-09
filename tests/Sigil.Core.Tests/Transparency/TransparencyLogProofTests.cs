using Sigil.Signing;
using Sigil.Transparency;

namespace Sigil.Core.Tests.Transparency;

public class TransparencyLogProofTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _logPath;

    public TransparencyLogProofTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
        _logPath = Path.Combine(_tempDir, ".sigil.log.jsonl");
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    private static void AppendEntries(TransparencyLog log, int count)
    {
        for (int i = 0; i < count; i++)
        {
            var envelope = new SignatureEnvelope
            {
                Subject = new SubjectDescriptor
                {
                    Name = $"file{i}.dll",
                    Digests = new Dictionary<string, string> { ["sha256"] = $"digest{i}" }
                },
                Signatures =
                [
                    new SignatureEntry
                    {
                        KeyId = "sha256:key1",
                        Algorithm = "ecdsa-p256",
                        PublicKey = "BQAA",
                        Value = Convert.ToBase64String([(byte)(i + 1), (byte)(i + 2)]),
                        Timestamp = "2026-01-15T10:00:00Z"
                    }
                ]
            };
            log.Append(envelope);
        }
    }

    [Fact]
    public void Inclusion_proof_verifies()
    {
        var log = new TransparencyLog(_logPath);
        AppendEntries(log, 5);

        var result = log.GetInclusionProof(2);

        Assert.True(result.IsSuccess);
        var proof = result.Value;
        Assert.Equal(2, proof.LeafIndex);
        Assert.Equal(5, proof.TreeSize);

        // Verify the proof with the actual leaf hash
        var entries = log.ReadEntries().Value;
        var leafHash = Convert.FromHexString(entries[2].LeafHash);
        Assert.True(MerkleTree.VerifyInclusionProof(proof, leafHash));
    }

    [Fact]
    public void Inclusion_proof_out_of_range_fails()
    {
        var log = new TransparencyLog(_logPath);
        AppendEntries(log, 3);

        var result = log.GetInclusionProof(10);

        Assert.False(result.IsSuccess);
        Assert.Equal(TransparencyErrorKind.InvalidProof, result.ErrorKind);
    }

    [Fact]
    public void Consistency_proof_verifies()
    {
        var log = new TransparencyLog(_logPath);
        AppendEntries(log, 6);

        var result = log.GetConsistencyProof(3);

        Assert.True(result.IsSuccess);
        var proof = result.Value;
        Assert.Equal(3, proof.OldSize);
        Assert.Equal(6, proof.NewSize);
        Assert.True(MerkleTree.VerifyConsistencyProof(proof));
    }

    [Fact]
    public void Consistency_proof_out_of_range_fails()
    {
        var log = new TransparencyLog(_logPath);
        AppendEntries(log, 3);

        var result = log.GetConsistencyProof(5);

        Assert.False(result.IsSuccess);
        Assert.Equal(TransparencyErrorKind.InvalidProof, result.ErrorKind);
    }

    [Fact]
    public void ReadEntries_with_limit_and_offset()
    {
        var log = new TransparencyLog(_logPath);
        AppendEntries(log, 10);

        var result = log.ReadEntries(limit: 3, offset: 2);

        Assert.True(result.IsSuccess);
        Assert.Equal(3, result.Value.Count);
        Assert.Equal(2, result.Value[0].Index);
        Assert.Equal(4, result.Value[2].Index);
    }
}
