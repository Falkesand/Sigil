using System.Security.Cryptography;

namespace Sigil.Pe;

/// <summary>
/// Computes the Authenticode PE image hash as defined in the Windows Authenticode specification.
/// The hash excludes the CheckSum field, the Certificate Table directory entry,
/// and the certificate data itself.
/// </summary>
public static class AuthenticodeHasher
{
    public static AuthenticodeResult<byte[]> ComputeHash(
        ReadOnlySpan<byte> peData, PeFile peFile, HashAlgorithmName hashAlgorithm)
    {
        ArgumentNullException.ThrowIfNull(peFile);

        using var hash = IncrementalHash.CreateHash(hashAlgorithm);

        // 1. Hash from start of file up to (but not including) the CheckSum field
        int offset = 0;
        int checkSumOffset = peFile.CheckSumOffset;
        hash.AppendData(peData[offset..checkSumOffset]);
        offset = checkSumOffset + 4; // Skip 4-byte CheckSum

        // 2. Hash from after CheckSum to (but not including) the Certificate Table directory entry
        int certDirOffset = peFile.CertTableDirectoryOffset;
        hash.AppendData(peData[offset..certDirOffset]);
        offset = certDirOffset + 8; // Skip 8-byte directory entry (RVA + Size)

        // 3. Hash from after Certificate Table directory to end of headers
        uint sizeOfHeaders = peFile.SizeOfHeaders;
        if (offset < (int)sizeOfHeaders)
        {
            hash.AppendData(peData[offset..(int)sizeOfHeaders]);
        }

        // 4. Hash sections in ascending PointerToRawData order (already sorted by PeFile.Parse)
        foreach (var section in peFile.Sections)
        {
            if (section.SizeOfRawData == 0)
                continue;

            // Use long arithmetic to prevent overflow with large section values
            long sectionStartL = section.PointerToRawData;
            long sectionEndL = sectionStartL + section.SizeOfRawData;
            if (sectionEndL > peData.Length)
                return AuthenticodeResult<byte[]>.Fail(
                    AuthenticodeErrorKind.InvalidPeFormat,
                    $"Section '{section.Name}' extends beyond file bounds.");

            hash.AppendData(peData[(int)sectionStartL..(int)sectionEndL]);
        }

        // 5. Hash any trailing data between last section end and certificate table
        // (some PE files have extra data appended after sections)
        int lastSectionEnd = 0;
        foreach (var section in peFile.Sections)
        {
            if (section.SizeOfRawData == 0)
                continue;

            long sectionEndL = (long)section.PointerToRawData + section.SizeOfRawData;
            int sectionEnd = (int)Math.Min(sectionEndL, peData.Length);
            if (sectionEnd > lastSectionEnd)
                lastSectionEnd = sectionEnd;
        }

        // Determine where trailing data ends (before cert table, or EOF if no cert table)
        int trailingEnd = peFile.CertTableSize > 0
            ? (int)peFile.CertTableFileOffset
            : peData.Length;

        if (lastSectionEnd < trailingEnd)
        {
            hash.AppendData(peData[lastSectionEnd..trailingEnd]);
        }

        return AuthenticodeResult<byte[]>.Ok(hash.GetCurrentHash());
    }
}
