using System.Text.Json;
using Sigil.Transparency.Remote;

namespace Sigil.Core.Tests.Transparency.Remote;

public class RekorEntryParserTests
{
    [Fact]
    public void ParseResponse_valid_entry()
    {
        var json = JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["24658612345abcdef"] = new
            {
                logIndex = 12345,
                verification = new
                {
                    signedEntryTimestamp = "dGVzdA==",
                    inclusionProof = new
                    {
                        logIndex = 12345,
                        treeSize = 50000,
                        rootHash = "aabbccdd",
                        hashes = (string[])["1111", "2222", "3333"]
                    }
                }
            }
        });

        var result = RekorEntryParser.ParseResponse(json, "https://rekor.sigstore.dev");

        Assert.True(result.IsSuccess);
        Assert.Equal("https://rekor.sigstore.dev", result.Value.LogUrl);
        Assert.Equal(12345, result.Value.LogIndex);
        Assert.Equal("dGVzdA==", result.Value.SignedCheckpoint);
        Assert.Equal(12345, result.Value.InclusionProof.LeafIndex);
        Assert.Equal(50000, result.Value.InclusionProof.TreeSize);
        Assert.Equal(3, result.Value.InclusionProof.Hashes.Count);
    }

    [Fact]
    public void ParseResponse_without_inclusion_proof()
    {
        var json = JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["uuid123"] = new
            {
                logIndex = 99,
                verification = new
                {
                    signedEntryTimestamp = "c2V0"
                }
            }
        });

        var result = RekorEntryParser.ParseResponse(json, "https://rekor.sigstore.dev");

        Assert.True(result.IsSuccess);
        Assert.Equal(99, result.Value.LogIndex);
        Assert.Equal("c2V0", result.Value.SignedCheckpoint);
        // When no inclusion proof, creates placeholder
        Assert.NotNull(result.Value.InclusionProof);
        Assert.Equal(99, result.Value.InclusionProof.LeafIndex);
    }

    [Fact]
    public void ParseResponse_missing_logIndex_fails()
    {
        var json = JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["uuid123"] = new { noIndex = true }
        });

        var result = RekorEntryParser.ParseResponse(json, "https://rekor.sigstore.dev");

        Assert.False(result.IsSuccess);
        Assert.Equal(RemoteLogErrorKind.InvalidResponse, result.ErrorKind);
    }

    [Fact]
    public void ParseResponse_empty_object_fails()
    {
        var result = RekorEntryParser.ParseResponse("{}", "https://rekor.sigstore.dev");

        Assert.False(result.IsSuccess);
        Assert.Equal(RemoteLogErrorKind.InvalidResponse, result.ErrorKind);
    }

    [Fact]
    public void ParseResponse_invalid_json_fails()
    {
        var result = RekorEntryParser.ParseResponse("not-json{", "https://rekor.sigstore.dev");

        Assert.False(result.IsSuccess);
        Assert.Equal(RemoteLogErrorKind.InvalidResponse, result.ErrorKind);
    }

    [Fact]
    public void ParseResponse_array_fails()
    {
        var result = RekorEntryParser.ParseResponse("[1,2,3]", "https://rekor.sigstore.dev");

        Assert.False(result.IsSuccess);
        Assert.Equal(RemoteLogErrorKind.InvalidResponse, result.ErrorKind);
    }

    [Fact]
    public void SpkiToPem_produces_valid_pem()
    {
        var base64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtest";

        var pem = RekorEntryParser.SpkiToPem(base64);

        Assert.StartsWith("-----BEGIN PUBLIC KEY-----", pem);
        Assert.Contains(base64, pem);
        Assert.Contains("-----END PUBLIC KEY-----", pem);
    }

    [Fact]
    public void SpkiToPem_wraps_long_lines()
    {
        // 100 chars of base64
        var base64 = new string('A', 100);

        var pem = RekorEntryParser.SpkiToPem(base64);
        var lines = pem.Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries);

        // Header, up to 2 data lines (64+36), footer
        Assert.Equal("-----BEGIN PUBLIC KEY-----", lines[0]);
        Assert.Equal(64, lines[1].Length); // First data line
        Assert.Equal(36, lines[2].Length); // Second data line
        Assert.Equal("-----END PUBLIC KEY-----", lines[3]);
    }

    [Fact]
    public void SpkiToPem_rejects_empty()
    {
        Assert.Throws<ArgumentException>(() => RekorEntryParser.SpkiToPem(""));
    }
}
