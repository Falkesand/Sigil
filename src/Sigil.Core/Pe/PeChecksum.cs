using System.Buffers.Binary;

namespace Sigil.Pe;

/// <summary>
/// Computes the PE optional header checksum (16-bit fold-and-carry, plus file length).
/// This is the same algorithm used by Windows MapFileAndCheckSum.
/// </summary>
public static class PeChecksum
{
    public static uint Compute(ReadOnlySpan<byte> peData, int checkSumOffset)
    {
        long checksum = 0;
        int length = peData.Length;

        // Process file as uint16 words
        for (int i = 0; i < length - 1; i += 2)
        {
            // Skip the CheckSum field (4 bytes = 2 uint16 words)
            if (i == checkSumOffset || i == checkSumOffset + 2)
                continue;

            ushort word = BinaryPrimitives.ReadUInt16LittleEndian(peData[i..]);
            checksum += word;

            // Fold carry bits
            checksum = (checksum & 0xFFFF) + (checksum >> 16);
        }

        // Handle trailing odd byte
        if (length % 2 != 0)
        {
            checksum += peData[length - 1];
            checksum = (checksum & 0xFFFF) + (checksum >> 16);
        }

        // Final fold
        checksum = (checksum & 0xFFFF) + (checksum >> 16);

        // Add file length
        checksum += (uint)length;

        return (uint)checksum;
    }
}
