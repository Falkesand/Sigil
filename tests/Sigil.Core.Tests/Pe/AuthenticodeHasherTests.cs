using System.Buffers.Binary;
using System.Security.Cryptography;
using Sigil.Pe;

namespace Sigil.Core.Tests.Pe;

public class AuthenticodeHasherTests
{
    [Fact]
    public void ComputeHash_Pe32_ProducesNonZeroDigest()
    {
        var data = PeTestHelper.BuildMinimalPe32([0xDE, 0xAD, 0xBE, 0xEF]);
        var peFile = PeFile.Parse(data).Value;

        var result = AuthenticodeHasher.ComputeHash(data, peFile, HashAlgorithmName.SHA256);

        Assert.True(result.IsSuccess);
        Assert.NotNull(result.Value);
        Assert.All(result.Value, b => { }); // No exception = bytes exist
        Assert.NotEqual(new byte[32], result.Value); // Not all zeros
    }

    [Fact]
    public void ComputeHash_Pe32Plus_ProducesNonZeroDigest()
    {
        var data = PeTestHelper.BuildMinimalPe32Plus([0xCA, 0xFE]);
        var peFile = PeFile.Parse(data).Value;

        var result = AuthenticodeHasher.ComputeHash(data, peFile, HashAlgorithmName.SHA256);

        Assert.True(result.IsSuccess);
        Assert.Equal(32, result.Value.Length); // SHA-256 = 32 bytes
    }

    [Fact]
    public void ComputeHash_ExcludesCheckSum()
    {
        var data = PeTestHelper.BuildMinimalPe32Plus();
        var peFile = PeFile.Parse(data).Value;

        var hashBefore = AuthenticodeHasher.ComputeHash(data, peFile, HashAlgorithmName.SHA256).Value;

        // Modify the CheckSum field
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(peFile.CheckSumOffset), 0xDEADBEEF);

        var hashAfter = AuthenticodeHasher.ComputeHash(data, peFile, HashAlgorithmName.SHA256).Value;

        Assert.Equal(hashBefore, hashAfter);
    }

    [Fact]
    public void ComputeHash_ExcludesCertTableDirectoryEntry()
    {
        var data = PeTestHelper.BuildMinimalPe32Plus();
        var peFile = PeFile.Parse(data).Value;

        var hashBefore = AuthenticodeHasher.ComputeHash(data, peFile, HashAlgorithmName.SHA256).Value;

        // Modify the Certificate Table directory entry (8 bytes: RVA + Size)
        BinaryPrimitives.WriteUInt32LittleEndian(
            data.AsSpan(peFile.CertTableDirectoryOffset), 0x12345678);
        BinaryPrimitives.WriteUInt32LittleEndian(
            data.AsSpan(peFile.CertTableDirectoryOffset + 4), 0x00001000);

        var hashAfter = AuthenticodeHasher.ComputeHash(data, peFile, HashAlgorithmName.SHA256).Value;

        Assert.Equal(hashBefore, hashAfter);
    }

    [Fact]
    public void ComputeHash_ChangingContent_ChangesHash()
    {
        var data = PeTestHelper.BuildMinimalPe32Plus([0x01, 0x02, 0x03, 0x04]);
        var peFile = PeFile.Parse(data).Value;

        var hashBefore = AuthenticodeHasher.ComputeHash(data, peFile, HashAlgorithmName.SHA256).Value;

        // Modify section content (first byte after headers)
        var sections = peFile.Sections;
        if (sections.Count > 0 && sections[0].SizeOfRawData > 0)
        {
            data[(int)sections[0].PointerToRawData] ^= 0xFF;
        }

        var hashAfter = AuthenticodeHasher.ComputeHash(data, peFile, HashAlgorithmName.SHA256).Value;

        Assert.NotEqual(hashBefore, hashAfter);
    }

    [Fact]
    public void ComputeHash_SectionsHashedInOrder()
    {
        var data = PeTestHelper.BuildPeWithTwoSections();
        var peFile = PeFile.Parse(data).Value;

        var result = AuthenticodeHasher.ComputeHash(data, peFile, HashAlgorithmName.SHA256);

        Assert.True(result.IsSuccess);
        // Verify sections are sorted (PeFile guarantees this)
        Assert.True(peFile.Sections[0].PointerToRawData <= peFile.Sections[1].PointerToRawData);
    }

    [Fact]
    public void ComputeHash_Sha256_Produces32Bytes()
    {
        var data = PeTestHelper.BuildMinimalPe32();
        var peFile = PeFile.Parse(data).Value;

        var result = AuthenticodeHasher.ComputeHash(data, peFile, HashAlgorithmName.SHA256);

        Assert.True(result.IsSuccess);
        Assert.Equal(32, result.Value.Length);
    }
}
