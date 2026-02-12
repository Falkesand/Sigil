using System.Buffers.Binary;

namespace Sigil.Core.Tests.Pe;

/// <summary>
/// Builds minimal PE32 and PE32+ binaries for testing.
/// These are structurally valid PE files but not executable.
/// </summary>
internal static class PeTestHelper
{
    /// <summary>
    /// Builds a minimal PE32 (32-bit) binary with one .text section.
    /// </summary>
    public static byte[] BuildMinimalPe32(byte[]? sectionContent = null)
    {
        return BuildMinimalPe(0x10B, sectionContent);
    }

    /// <summary>
    /// Builds a minimal PE32+ (64-bit) binary with one .text section.
    /// </summary>
    public static byte[] BuildMinimalPe32Plus(byte[]? sectionContent = null)
    {
        return BuildMinimalPe(0x20B, sectionContent);
    }

    private static byte[] BuildMinimalPe(ushort magic, byte[]? sectionContent)
    {
        sectionContent ??= new byte[512];
        // Ensure section content is file-aligned (512 bytes)
        int sectionSize = ((sectionContent.Length + 511) / 512) * 512;

        // PE32: Optional Header = 96 + 16 data dir entries * 8 = 96 + 128 = 224 bytes
        // PE32+: Optional Header = 112 + 16 data dir entries * 8 = 112 + 128 = 240 bytes
        int standardFieldsSize = magic == 0x10B ? 96 : 112;
        int dataDirectorySize = 16 * 8; // 16 entries, 8 bytes each
        int optionalHeaderSize = standardFieldsSize + dataDirectorySize;

        int dosHeaderSize = 64; // Minimal DOS header
        int peSignatureSize = 4; // "PE\0\0"
        int coffHeaderSize = 20;
        int sectionHeaderSize = 40; // 1 section * 40 bytes
        int headersSize = dosHeaderSize + peSignatureSize + coffHeaderSize + optionalHeaderSize + sectionHeaderSize;
        // Align headers to 512 bytes
        int alignedHeadersSize = ((headersSize + 511) / 512) * 512;

        int totalSize = alignedHeadersSize + sectionSize;
        var pe = new byte[totalSize];

        int offset = 0;

        // DOS Header
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(0), 0x5A4D); // e_magic = "MZ"
        BinaryPrimitives.WriteInt32LittleEndian(pe.AsSpan(0x3C), dosHeaderSize); // e_lfanew → PE sig at offset 64
        offset = dosHeaderSize;

        // PE Signature
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(offset), 0x00004550); // "PE\0\0"
        offset += peSignatureSize;

        // COFF Header (20 bytes)
        int coffOffset = offset;
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(coffOffset + 0), 0x014C); // Machine: i386 (or 0x8664 for x64, doesn't matter for parsing)
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(coffOffset + 2), 1); // NumberOfSections
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(coffOffset + 16), (ushort)optionalHeaderSize); // SizeOfOptionalHeader
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(coffOffset + 18), 0x0002); // Characteristics: EXECUTABLE_IMAGE
        offset += coffHeaderSize;

        // Optional Header
        int optHeaderOffset = offset;
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(optHeaderOffset), magic); // Magic

        // SizeOfHeaders at offset 60 in Optional Header
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(optHeaderOffset + 60), (uint)alignedHeadersSize);

        // CheckSum at offset 64 in Optional Header (initially 0)
        // Already 0 from array init

        // NumberOfRvaAndSizes: at offset (standardFieldsSize - 4) in Optional Header
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(optHeaderOffset + standardFieldsSize - 4), 16);

        // Data Directories: all zeros (no cert table yet)
        // The cert table is entry #4 (index 4), at offset standardFieldsSize + 4*8
        // Left as zeros for now

        offset += optionalHeaderSize;

        // Section Header: .text
        int sectionHeaderOffset = offset;
        System.Text.Encoding.ASCII.GetBytes(".text\0\0\0", pe.AsSpan(sectionHeaderOffset, 8));
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(sectionHeaderOffset + 8), (uint)sectionContent.Length); // VirtualSize
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(sectionHeaderOffset + 12), 0x1000); // VirtualAddress
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(sectionHeaderOffset + 16), (uint)sectionSize); // SizeOfRawData
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(sectionHeaderOffset + 20), (uint)alignedHeadersSize); // PointerToRawData

        // Copy section content
        sectionContent.AsSpan().CopyTo(pe.AsSpan(alignedHeadersSize));

        return pe;
    }

    /// <summary>
    /// Builds a PE with two sections, sorted/unsorted by PointerToRawData.
    /// </summary>
    public static byte[] BuildPeWithTwoSections()
    {
        const ushort magic = 0x20B; // PE32+
        int standardFieldsSize = 112;
        int dataDirectorySize = 16 * 8;
        int optionalHeaderSize = standardFieldsSize + dataDirectorySize;

        int dosHeaderSize = 64;
        int peSignatureSize = 4;
        int coffHeaderSize = 20;
        int sectionHeadersSize = 2 * 40; // 2 sections
        int headersSize = dosHeaderSize + peSignatureSize + coffHeaderSize + optionalHeaderSize + sectionHeadersSize;
        int alignedHeadersSize = ((headersSize + 511) / 512) * 512;

        int section1Size = 512;
        int section2Size = 512;
        int totalSize = alignedHeadersSize + section1Size + section2Size;
        var pe = new byte[totalSize];

        // DOS Header
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(0), 0x5A4D);
        BinaryPrimitives.WriteInt32LittleEndian(pe.AsSpan(0x3C), dosHeaderSize);

        // PE Signature
        int offset = dosHeaderSize;
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(offset), 0x00004550);
        offset += peSignatureSize;

        // COFF Header
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(offset + 0), 0x8664);
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(offset + 2), 2); // 2 sections
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(offset + 16), (ushort)optionalHeaderSize);
        offset += coffHeaderSize;

        // Optional Header
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(offset), magic);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(offset + 60), (uint)alignedHeadersSize);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(offset + standardFieldsSize - 4), 16);
        offset += optionalHeaderSize;

        // Section 1: .data (placed SECOND in file — higher PointerToRawData)
        int sec1HeaderOffset = offset;
        System.Text.Encoding.ASCII.GetBytes(".data\0\0\0", pe.AsSpan(sec1HeaderOffset, 8));
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(sec1HeaderOffset + 8), 256);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(sec1HeaderOffset + 12), 0x2000);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(sec1HeaderOffset + 16), (uint)section2Size);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(sec1HeaderOffset + 20), (uint)(alignedHeadersSize + section1Size));
        offset += 40;

        // Section 2: .text (placed FIRST in file — lower PointerToRawData)
        int sec2HeaderOffset = offset;
        System.Text.Encoding.ASCII.GetBytes(".text\0\0\0", pe.AsSpan(sec2HeaderOffset, 8));
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(sec2HeaderOffset + 8), 128);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(sec2HeaderOffset + 12), 0x1000);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(sec2HeaderOffset + 16), (uint)section1Size);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(sec2HeaderOffset + 20), (uint)alignedHeadersSize);

        // Write some recognizable content
        pe[alignedHeadersSize] = 0xCC; // .text section
        pe[alignedHeadersSize + section1Size] = 0xDD; // .data section

        return pe;
    }
}
