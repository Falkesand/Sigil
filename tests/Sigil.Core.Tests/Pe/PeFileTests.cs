using Sigil.Pe;

namespace Sigil.Core.Tests.Pe;

public class PeFileTests
{
    [Fact]
    public void Parse_ValidPe32_Succeeds()
    {
        var data = PeTestHelper.BuildMinimalPe32();

        var result = PeFile.Parse(data);

        Assert.True(result.IsSuccess);
        Assert.Equal(PeFormat.PE32, result.Value.Format);
    }

    [Fact]
    public void Parse_ValidPe32Plus_Succeeds()
    {
        var data = PeTestHelper.BuildMinimalPe32Plus();

        var result = PeFile.Parse(data);

        Assert.True(result.IsSuccess);
        Assert.Equal(PeFormat.PE32Plus, result.Value.Format);
    }

    [Fact]
    public void Parse_InvalidMzSignature_ReturnsNotPortableExecutable()
    {
        var data = new byte[512];
        data[0] = 0xFF; // Not 'M'
        data[1] = 0xFF; // Not 'Z'

        var result = PeFile.Parse(data);

        Assert.False(result.IsSuccess);
        Assert.Equal(AuthenticodeErrorKind.NotPortableExecutable, result.ErrorKind);
        Assert.Contains("MZ", result.ErrorMessage);
    }

    [Fact]
    public void Parse_InvalidPeSignature_ReturnsNotPortableExecutable()
    {
        var data = PeTestHelper.BuildMinimalPe32();
        // Corrupt PE signature at e_lfanew (offset 64)
        data[64] = 0xFF;

        var result = PeFile.Parse(data);

        Assert.False(result.IsSuccess);
        Assert.Equal(AuthenticodeErrorKind.NotPortableExecutable, result.ErrorKind);
        Assert.Contains("PE", result.ErrorMessage);
    }

    [Fact]
    public void Parse_TruncatedFile_ReturnsInvalidPeFormat()
    {
        var data = new byte[10]; // Way too small
        data[0] = 0x4D; // 'M'
        data[1] = 0x5A; // 'Z'

        var result = PeFile.Parse(data);

        Assert.False(result.IsSuccess);
        Assert.Equal(AuthenticodeErrorKind.InvalidPeFormat, result.ErrorKind);
    }

    [Fact]
    public void Parse_UnsupportedMagic_ReturnsInvalidPeFormat()
    {
        var data = PeTestHelper.BuildMinimalPe32();
        // Find Optional Header offset and corrupt magic
        int eLfanew = BitConverter.ToInt32(data, 0x3C);
        int optHeaderOffset = eLfanew + 4 + 20; // PE sig + COFF header
        // Write unsupported magic
        data[optHeaderOffset] = 0x00;
        data[optHeaderOffset + 1] = 0x00;

        var result = PeFile.Parse(data);

        Assert.False(result.IsSuccess);
        Assert.Equal(AuthenticodeErrorKind.InvalidPeFormat, result.ErrorKind);
        Assert.Contains("magic", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_CorrectCheckSumOffset_ForPe32()
    {
        var data = PeTestHelper.BuildMinimalPe32();

        var result = PeFile.Parse(data);

        Assert.True(result.IsSuccess);
        var pe = result.Value;
        // CheckSum is at Optional Header + 64
        int eLfanew = BitConverter.ToInt32(data, 0x3C);
        int expectedCheckSumOffset = eLfanew + 4 + 20 + 64;
        Assert.Equal(expectedCheckSumOffset, pe.CheckSumOffset);
    }

    [Fact]
    public void Parse_CorrectCheckSumOffset_ForPe32Plus()
    {
        var data = PeTestHelper.BuildMinimalPe32Plus();

        var result = PeFile.Parse(data);

        Assert.True(result.IsSuccess);
        var pe = result.Value;
        int eLfanew = BitConverter.ToInt32(data, 0x3C);
        int expectedCheckSumOffset = eLfanew + 4 + 20 + 64;
        Assert.Equal(expectedCheckSumOffset, pe.CheckSumOffset);
    }

    [Fact]
    public void Parse_SectionsSortedByPointerToRawData()
    {
        var data = PeTestHelper.BuildPeWithTwoSections();

        var result = PeFile.Parse(data);

        Assert.True(result.IsSuccess);
        var pe = result.Value;
        Assert.Equal(2, pe.Sections.Count);
        // Sections should be sorted by PointerToRawData ascending
        Assert.True(pe.Sections[0].PointerToRawData <= pe.Sections[1].PointerToRawData);
        Assert.Equal(".text", pe.Sections[0].Name);
        Assert.Equal(".data", pe.Sections[1].Name);
    }

    [Fact]
    public void Parse_NoCertTable_HasZeroOffsetAndSize()
    {
        var data = PeTestHelper.BuildMinimalPe32Plus();

        var result = PeFile.Parse(data);

        Assert.True(result.IsSuccess);
        var pe = result.Value;
        Assert.Equal(0u, pe.CertTableFileOffset);
        Assert.Equal(0u, pe.CertTableSize);
    }

    [Fact]
    public void Parse_FileTooSmall_ReturnsInvalidPeFormat()
    {
        var data = new byte[2]; // Minimum is 64

        var result = PeFile.Parse(data);

        Assert.False(result.IsSuccess);
        Assert.Equal(AuthenticodeErrorKind.InvalidPeFormat, result.ErrorKind);
        Assert.Contains("too small", result.ErrorMessage);
    }

    [Fact]
    public void Parse_SectionBoundsOverflow_ReturnsInvalidPeFormat()
    {
        // Build a valid PE and then corrupt the section header so
        // PointerToRawData + SizeOfRawData overflows uint32.
        var data = PeTestHelper.BuildMinimalPe32Plus();
        int eLfanew = BitConverter.ToInt32(data, 0x3C);
        int coffHeaderOffset = eLfanew + 4;
        ushort sizeOfOptionalHeader = BitConverter.ToUInt16(data, coffHeaderOffset + 16);
        int sectionHeaderOffset = coffHeaderOffset + 20 + sizeOfOptionalHeader;

        // Set PointerToRawData to 0xFFFFFF00 and SizeOfRawData to 0x200 → overflow
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(
            data.AsSpan(sectionHeaderOffset + 20), 0xFFFFFF00);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(
            data.AsSpan(sectionHeaderOffset + 16), 0x200);

        var result = PeFile.Parse(data);

        Assert.False(result.IsSuccess);
        Assert.Equal(AuthenticodeErrorKind.InvalidPeFormat, result.ErrorKind);
        Assert.Contains("overflow", result.ErrorMessage);
    }
}
