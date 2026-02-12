using System.Buffers.Binary;

namespace Sigil.Pe;

/// <summary>
/// Parses PE (Portable Executable) file headers for Authenticode signing and verification.
/// Pure managed implementation — works cross-platform.
/// </summary>
public sealed class PeFile
{
    private const ushort MzSignature = 0x5A4D;
    private const uint PeSignature = 0x00004550; // "PE\0\0"
    private const int MinPeSize = 64; // Minimum: DOS header

    // Optional Header offsets (relative to Optional Header start)
    private const int CheckSumOffsetInOptionalHeader = 64;

    // Data Directory index for Certificate Table
    private const int CertTableDirectoryIndex = 4;

    public PeFormat Format { get; }
    public int CheckSumOffset { get; }
    public int CertTableDirectoryOffset { get; }
    public uint CertTableFileOffset { get; }
    public uint CertTableSize { get; }
    public IReadOnlyList<PeSectionHeader> Sections { get; }
    public uint SizeOfHeaders { get; }

    private PeFile(
        PeFormat format,
        int checkSumOffset,
        int certTableDirectoryOffset,
        uint certTableFileOffset,
        uint certTableSize,
        IReadOnlyList<PeSectionHeader> sections,
        uint sizeOfHeaders)
    {
        Format = format;
        CheckSumOffset = checkSumOffset;
        CertTableDirectoryOffset = certTableDirectoryOffset;
        CertTableFileOffset = certTableFileOffset;
        CertTableSize = certTableSize;
        Sections = sections;
        SizeOfHeaders = sizeOfHeaders;
    }

    public static AuthenticodeResult<PeFile> Parse(ReadOnlySpan<byte> data)
    {
        if (data.Length < MinPeSize)
            return AuthenticodeResult<PeFile>.Fail(
                AuthenticodeErrorKind.InvalidPeFormat,
                $"File too small to be a valid PE ({data.Length} bytes, minimum {MinPeSize}).");

        // Validate MZ signature
        ushort mzSig = BinaryPrimitives.ReadUInt16LittleEndian(data);
        if (mzSig != MzSignature)
            return AuthenticodeResult<PeFile>.Fail(
                AuthenticodeErrorKind.NotPortableExecutable,
                "Missing MZ signature — not a PE file.");

        // Read e_lfanew (offset to PE signature) at offset 0x3C
        if (data.Length < 0x3C + 4)
            return AuthenticodeResult<PeFile>.Fail(
                AuthenticodeErrorKind.InvalidPeFormat,
                "File truncated before e_lfanew offset.");

        int eLfanew = BinaryPrimitives.ReadInt32LittleEndian(data[0x3C..]);
        if (eLfanew < 0 || eLfanew + 4 > data.Length)
            return AuthenticodeResult<PeFile>.Fail(
                AuthenticodeErrorKind.InvalidPeFormat,
                "e_lfanew points beyond file bounds.");

        // Validate PE signature
        uint peSig = BinaryPrimitives.ReadUInt32LittleEndian(data[eLfanew..]);
        if (peSig != PeSignature)
            return AuthenticodeResult<PeFile>.Fail(
                AuthenticodeErrorKind.NotPortableExecutable,
                "Missing PE\\0\\0 signature at e_lfanew.");

        // COFF Header starts at eLfanew + 4
        int coffHeaderOffset = eLfanew + 4;
        if (coffHeaderOffset + 20 > data.Length)
            return AuthenticodeResult<PeFile>.Fail(
                AuthenticodeErrorKind.InvalidPeFormat,
                "File truncated in COFF header.");

        ushort numberOfSections = BinaryPrimitives.ReadUInt16LittleEndian(data[(coffHeaderOffset + 2)..]);
        ushort sizeOfOptionalHeader = BinaryPrimitives.ReadUInt16LittleEndian(data[(coffHeaderOffset + 16)..]);

        // Optional Header starts after COFF Header (20 bytes)
        int optionalHeaderOffset = coffHeaderOffset + 20;
        if (optionalHeaderOffset + sizeOfOptionalHeader > data.Length)
            return AuthenticodeResult<PeFile>.Fail(
                AuthenticodeErrorKind.InvalidPeFormat,
                "File truncated in Optional Header.");

        if (sizeOfOptionalHeader < 2)
            return AuthenticodeResult<PeFile>.Fail(
                AuthenticodeErrorKind.InvalidPeFormat,
                "Optional Header too small.");

        // Read Optional Header magic
        ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(data[optionalHeaderOffset..]);
        PeFormat format;
        int dataDirectoryStart;

        if (magic == (ushort)PeFormat.PE32)
        {
            format = PeFormat.PE32;
            // PE32: Data Directories start at offset 96 within Optional Header
            dataDirectoryStart = optionalHeaderOffset + 96;
        }
        else if (magic == (ushort)PeFormat.PE32Plus)
        {
            format = PeFormat.PE32Plus;
            // PE32+: Data Directories start at offset 112 within Optional Header
            dataDirectoryStart = optionalHeaderOffset + 112;
        }
        else
        {
            return AuthenticodeResult<PeFile>.Fail(
                AuthenticodeErrorKind.InvalidPeFormat,
                $"Unsupported Optional Header magic: 0x{magic:X4}.");
        }

        // CheckSum is at offset 64 within Optional Header
        int checkSumOffset = optionalHeaderOffset + CheckSumOffsetInOptionalHeader;
        if (checkSumOffset + 4 > data.Length)
            return AuthenticodeResult<PeFile>.Fail(
                AuthenticodeErrorKind.InvalidPeFormat,
                "File truncated before CheckSum field.");

        // Read NumberOfRvaAndSizes
        int numDirEntriesOffset = dataDirectoryStart - 4;
        if (numDirEntriesOffset + 4 > data.Length)
            return AuthenticodeResult<PeFile>.Fail(
                AuthenticodeErrorKind.InvalidPeFormat,
                "File truncated before NumberOfRvaAndSizes.");

        uint numberOfRvaAndSizes = BinaryPrimitives.ReadUInt32LittleEndian(data[numDirEntriesOffset..]);

        // Certificate Table is directory entry #4 (index 4)
        int certTableDirOffset;
        uint certTableFileOffset = 0;
        uint certTableSize = 0;

        if (numberOfRvaAndSizes > CertTableDirectoryIndex)
        {
            // Each directory entry is 8 bytes (4 RVA + 4 Size)
            certTableDirOffset = dataDirectoryStart + (CertTableDirectoryIndex * 8);
            if (certTableDirOffset + 8 > data.Length)
                return AuthenticodeResult<PeFile>.Fail(
                    AuthenticodeErrorKind.InvalidPeFormat,
                    "File truncated before Certificate Table directory entry.");

            // For the Certificate Table, the "RVA" is actually a file offset (not virtual)
            certTableFileOffset = BinaryPrimitives.ReadUInt32LittleEndian(data[certTableDirOffset..]);
            certTableSize = BinaryPrimitives.ReadUInt32LittleEndian(data[(certTableDirOffset + 4)..]);
        }
        else
        {
            // No cert table directory entry — point offset to where it would be
            certTableDirOffset = dataDirectoryStart + (CertTableDirectoryIndex * 8);
        }

        // Validate cert table bounds if present (check for uint32 overflow first)
        if (certTableSize > 0)
        {
            if (certTableFileOffset > uint.MaxValue - certTableSize)
                return AuthenticodeResult<PeFile>.Fail(
                    AuthenticodeErrorKind.InvalidPeFormat,
                    "Certificate Table offset/size would overflow.");

            if (certTableFileOffset + certTableSize > (uint)data.Length)
                return AuthenticodeResult<PeFile>.Fail(
                    AuthenticodeErrorKind.InvalidPeFormat,
                    "Certificate Table extends beyond file bounds.");
        }

        // Read SizeOfHeaders from Optional Header (offset 60)
        int sizeOfHeadersOffset = optionalHeaderOffset + 60;
        if (sizeOfHeadersOffset + 4 > data.Length)
            return AuthenticodeResult<PeFile>.Fail(
                AuthenticodeErrorKind.InvalidPeFormat,
                "File truncated before SizeOfHeaders.");

        uint sizeOfHeaders = BinaryPrimitives.ReadUInt32LittleEndian(data[sizeOfHeadersOffset..]);

        // Parse section headers (after Optional Header)
        int sectionHeadersOffset = optionalHeaderOffset + sizeOfOptionalHeader;
        var sections = new List<PeSectionHeader>(numberOfSections);

        for (int i = 0; i < numberOfSections; i++)
        {
            int sectionOffset = sectionHeadersOffset + (i * 40);
            if (sectionOffset + 40 > data.Length)
                return AuthenticodeResult<PeFile>.Fail(
                    AuthenticodeErrorKind.InvalidPeFormat,
                    $"File truncated in section header {i}.");

            // Section name: 8 bytes, null-padded
            var nameBytes = data.Slice(sectionOffset, 8);
            int nameLen = nameBytes.IndexOf((byte)0);
            if (nameLen < 0) nameLen = 8;
            string name = System.Text.Encoding.ASCII.GetString(nameBytes[..nameLen]);

            uint virtualSize = BinaryPrimitives.ReadUInt32LittleEndian(data[(sectionOffset + 8)..]);
            uint virtualAddress = BinaryPrimitives.ReadUInt32LittleEndian(data[(sectionOffset + 12)..]);
            uint sizeOfRawData = BinaryPrimitives.ReadUInt32LittleEndian(data[(sectionOffset + 16)..]);
            uint pointerToRawData = BinaryPrimitives.ReadUInt32LittleEndian(data[(sectionOffset + 20)..]);

            // Validate section bounds (check for uint32 overflow first)
            if (sizeOfRawData > 0)
            {
                if (pointerToRawData > uint.MaxValue - sizeOfRawData)
                    return AuthenticodeResult<PeFile>.Fail(
                        AuthenticodeErrorKind.InvalidPeFormat,
                        $"Section '{name}' offset/size would overflow.");

                if (pointerToRawData + sizeOfRawData > (uint)data.Length)
                    return AuthenticodeResult<PeFile>.Fail(
                        AuthenticodeErrorKind.InvalidPeFormat,
                        $"Section '{name}' extends beyond file bounds.");
            }

            sections.Add(new PeSectionHeader(name, virtualSize, virtualAddress, sizeOfRawData, pointerToRawData));
        }

        // Sort sections by PointerToRawData (ascending) for Authenticode hash calculation
        sections.Sort((a, b) => a.PointerToRawData.CompareTo(b.PointerToRawData));

        return AuthenticodeResult<PeFile>.Ok(new PeFile(
            format,
            checkSumOffset,
            certTableDirOffset,
            certTableFileOffset,
            certTableSize,
            sections,
            sizeOfHeaders));
    }
}
