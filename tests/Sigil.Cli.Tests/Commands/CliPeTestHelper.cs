using System.Buffers.Binary;

namespace Sigil.Cli.Tests.Commands;

/// <summary>
/// Builds minimal PE binaries for CLI command testing.
/// </summary>
internal static class CliPeTestHelper
{
    public static byte[] BuildMinimalPe32Plus(byte[]? sectionContent = null)
    {
        sectionContent ??= new byte[512];
        int sectionSize = ((sectionContent.Length + 511) / 512) * 512;

        const ushort magic = 0x20B;
        const int standardFieldsSize = 112;
        int dataDirectorySize = 16 * 8;
        int optionalHeaderSize = standardFieldsSize + dataDirectorySize;

        int dosHeaderSize = 64;
        int peSignatureSize = 4;
        int coffHeaderSize = 20;
        int sectionHeaderSize = 40;
        int headersSize = dosHeaderSize + peSignatureSize + coffHeaderSize + optionalHeaderSize + sectionHeaderSize;
        int alignedHeadersSize = ((headersSize + 511) / 512) * 512;

        int totalSize = alignedHeadersSize + sectionSize;
        var pe = new byte[totalSize];

        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(0), 0x5A4D);
        BinaryPrimitives.WriteInt32LittleEndian(pe.AsSpan(0x3C), dosHeaderSize);

        int offset = dosHeaderSize;
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(offset), 0x00004550);
        offset += peSignatureSize;

        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(offset + 0), 0x8664);
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(offset + 2), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(offset + 16), (ushort)optionalHeaderSize);
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(offset + 18), 0x0002);
        offset += coffHeaderSize;

        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(offset), magic);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(offset + 60), (uint)alignedHeadersSize);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(offset + standardFieldsSize - 4), 16);
        offset += optionalHeaderSize;

        System.Text.Encoding.ASCII.GetBytes(".text\0\0\0", pe.AsSpan(offset, 8));
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(offset + 8), (uint)sectionContent.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(offset + 12), 0x1000);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(offset + 16), (uint)sectionSize);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(offset + 20), (uint)alignedHeadersSize);

        sectionContent.AsSpan().CopyTo(pe.AsSpan(alignedHeadersSize));

        return pe;
    }
}
