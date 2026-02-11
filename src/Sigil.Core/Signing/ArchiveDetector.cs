using System.IO.Compression;

namespace Sigil.Signing;

/// <summary>
/// Detects archive format by magic bytes and file extension.
/// </summary>
public static class ArchiveDetector
{
    private static readonly byte[] ZipMagic = [0x50, 0x4B, 0x03, 0x04];
    private static readonly byte[] GZipMagic = [0x1F, 0x8B];

    /// <summary>
    /// Detects the archive format of a file by its magic bytes and extension.
    /// Returns null if the format is not recognized.
    /// </summary>
    public static ArchiveFormat? Detect(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        if (!File.Exists(path))
            return null;

        using var stream = File.OpenRead(path);
        return Detect(stream, Path.GetFileName(path));
    }

    /// <summary>
    /// Detects the archive format from a stream with an optional file name hint.
    /// The stream position is restored after detection if the stream is seekable.
    /// Non-seekable streams will be left at an advanced position.
    /// Returns null if the format is not recognized.
    /// </summary>
    public static ArchiveFormat? Detect(Stream stream, string? fileName)
    {
        ArgumentNullException.ThrowIfNull(stream);

        var startPosition = stream.Position;
        try
        {
            // Try magic bytes first
            var header = new byte[262];
            var bytesRead = stream.Read(header, 0, header.Length);

            if (bytesRead >= 4 && header.AsSpan(0, 4).SequenceEqual(ZipMagic))
                return ArchiveFormat.Zip;

            if (bytesRead >= 2 && header.AsSpan(0, 2).SequenceEqual(GZipMagic))
                return ArchiveFormat.TarGz;

            if (bytesRead >= 263 && IsTarHeader(header))
                return ArchiveFormat.Tar;

            // Fall back to file extension
            return DetectByExtension(fileName);
        }
        finally
        {
            if (stream.CanSeek)
                stream.Position = startPosition;
        }
    }

    private static bool IsTarHeader(byte[] header)
    {
        // Check for "ustar" magic at offset 257
        return header[257] == (byte)'u'
            && header[258] == (byte)'s'
            && header[259] == (byte)'t'
            && header[260] == (byte)'a'
            && header[261] == (byte)'r';
    }

    private static ArchiveFormat? DetectByExtension(string? fileName)
    {
        if (fileName is null)
            return null;

        if (fileName.EndsWith(".zip", StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith(".nupkg", StringComparison.OrdinalIgnoreCase))
            return ArchiveFormat.Zip;

        if (fileName.EndsWith(".tar.gz", StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith(".tgz", StringComparison.OrdinalIgnoreCase))
            return ArchiveFormat.TarGz;

        if (fileName.EndsWith(".tar", StringComparison.OrdinalIgnoreCase))
            return ArchiveFormat.Tar;

        return null;
    }
}
