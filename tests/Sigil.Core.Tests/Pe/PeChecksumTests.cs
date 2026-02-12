using System.Buffers.Binary;
using Sigil.Pe;

namespace Sigil.Core.Tests.Pe;

public class PeChecksumTests
{
    [Fact]
    public void Compute_BasicChecksum_NonZero()
    {
        var data = PeTestHelper.BuildMinimalPe32Plus();
        var peFile = PeFile.Parse(data).Value;

        uint checksum = PeChecksum.Compute(data, peFile.CheckSumOffset);

        Assert.NotEqual(0u, checksum);
    }

    [Fact]
    public void Compute_Roundtrip_ChecksumIsStableAfterEmbedding()
    {
        var data = PeTestHelper.BuildMinimalPe32Plus();
        var peFile = PeFile.Parse(data).Value;

        // Compute checksum and embed it
        uint checksum1 = PeChecksum.Compute(data, peFile.CheckSumOffset);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(peFile.CheckSumOffset), checksum1);

        // Recompute — should produce the same value
        uint checksum2 = PeChecksum.Compute(data, peFile.CheckSumOffset);
        Assert.Equal(checksum1, checksum2);
    }

    [Fact]
    public void Compute_ZeroesOutCheckSumField()
    {
        var data = PeTestHelper.BuildMinimalPe32();
        var peFile = PeFile.Parse(data).Value;

        // Write a non-zero checksum
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(peFile.CheckSumOffset), 0xAAAAAAAA);

        uint checksum1 = PeChecksum.Compute(data, peFile.CheckSumOffset);

        // Write a different value to checksum field
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(peFile.CheckSumOffset), 0xBBBBBBBB);

        uint checksum2 = PeChecksum.Compute(data, peFile.CheckSumOffset);

        // Both should be equal since the field is excluded
        Assert.Equal(checksum1, checksum2);
    }
}
