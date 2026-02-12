using System.Security.Cryptography;
using Sigil.Pe;

namespace Sigil.Core.Tests.Pe;

public class SpcIndirectDataBuilderTests
{
    [Fact]
    public void Build_ProducesValidDer()
    {
        var digest = SHA256.HashData("test content"u8);

        byte[] spcContent = SpcIndirectDataBuilder.Build(digest, HashAlgorithmName.SHA256);

        Assert.NotNull(spcContent);
        Assert.True(spcContent.Length > 0);
        // DER SEQUENCE tag is 0x30
        Assert.Equal(0x30, spcContent[0]);
    }

    [Fact]
    public void Build_ContainsSpcPeImageDataOid()
    {
        var digest = SHA256.HashData("test"u8);

        byte[] spcContent = SpcIndirectDataBuilder.Build(digest, HashAlgorithmName.SHA256);

        // The OID 1.3.6.1.4.1.311.2.1.15 should be encoded in the DER
        // DER encoding of this OID: 06 0A 2B 06 01 04 01 82 37 02 01 0F
        byte[] oidBytes = [0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0F];
        Assert.True(ContainsSubsequence(spcContent, oidBytes));
    }

    [Fact]
    public void Build_ContainsCorrectDigest()
    {
        var digest = SHA256.HashData("known content"u8);

        byte[] spcContent = SpcIndirectDataBuilder.Build(digest, HashAlgorithmName.SHA256);

        // The digest should appear as-is in the DER output (inside OCTET STRING)
        Assert.True(ContainsSubsequence(spcContent, digest));
    }

    [Fact]
    public void Build_ContainsSha256AlgorithmOid()
    {
        var digest = SHA256.HashData("algo test"u8);

        byte[] spcContent = SpcIndirectDataBuilder.Build(digest, HashAlgorithmName.SHA256);

        // SHA-256 OID: 2.16.840.1.101.3.4.2.1
        // DER encoding: 06 09 60 86 48 01 65 03 04 02 01
        byte[] sha256OidBytes = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
        Assert.True(ContainsSubsequence(spcContent, sha256OidBytes));
    }

    [Fact]
    public void RoundTrip_ParseReturnsOriginalDigestAndOid()
    {
        var digest = SHA256.HashData("roundtrip test"u8);

        byte[] spcContent = SpcIndirectDataBuilder.Build(digest, HashAlgorithmName.SHA256);
        var (parsedDigest, parsedOid) = SpcIndirectDataBuilder.Parse(spcContent);

        Assert.Equal(digest, parsedDigest);
        Assert.Equal("2.16.840.1.101.3.4.2.1", parsedOid);
    }

    private static bool ContainsSubsequence(byte[] haystack, byte[] needle)
    {
        for (int i = 0; i <= haystack.Length - needle.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j])
                {
                    match = false;
                    break;
                }
            }
            if (match)
                return true;
        }
        return false;
    }
}
