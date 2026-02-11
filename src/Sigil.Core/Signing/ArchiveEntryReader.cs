using System.Formats.Tar;
using System.IO.Compression;

namespace Sigil.Signing;

/// <summary>
/// Reads entries from archive files (ZIP, tar.gz, tar).
/// Enforces a per-entry size limit to prevent zip bomb attacks.
/// </summary>
public static class ArchiveEntryReader
{
    /// <summary>
    /// Maximum decompressed entry size (500 MB). Protects against zip bomb attacks.
    /// </summary>
    internal const long MaxEntrySize = 500L * 1024 * 1024;
    /// <summary>
    /// Lists all file entries in an archive (directories are excluded).
    /// </summary>
    public static IReadOnlyList<ArchiveEntryInfo> ListEntries(string archivePath, ArchiveFormat format)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(archivePath);

        return format switch
        {
            ArchiveFormat.Zip => ListZipEntries(archivePath),
            ArchiveFormat.TarGz => ListTarEntries(archivePath, gzipped: true),
            ArchiveFormat.Tar => ListTarEntries(archivePath, gzipped: false),
            _ => throw new ArgumentOutOfRangeException(nameof(format))
        };
    }

    /// <summary>
    /// Opens a single entry from an archive and returns its content as a stream.
    /// The caller must dispose the returned stream.
    /// </summary>
    public static Stream OpenEntry(string archivePath, ArchiveFormat format, string entryPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(archivePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(entryPath);

        return format switch
        {
            ArchiveFormat.Zip => OpenZipEntry(archivePath, entryPath),
            ArchiveFormat.TarGz => OpenTarEntry(archivePath, entryPath, gzipped: true),
            ArchiveFormat.Tar => OpenTarEntry(archivePath, entryPath, gzipped: false),
            _ => throw new ArgumentOutOfRangeException(nameof(format))
        };
    }

    /// <summary>
    /// Iterates all file entries in an archive, yielding entry info and content streams.
    /// Each content stream is valid only for the current iteration step.
    /// For tar archives, streams must be consumed before advancing.
    /// </summary>
    public static IEnumerable<(ArchiveEntryInfo Entry, Stream Content)> ReadEntries(
        string archivePath, ArchiveFormat format)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(archivePath);

        return format switch
        {
            ArchiveFormat.Zip => ReadZipEntries(archivePath),
            ArchiveFormat.TarGz => ReadTarEntries(archivePath, gzipped: true),
            ArchiveFormat.Tar => ReadTarEntries(archivePath, gzipped: false),
            _ => throw new ArgumentOutOfRangeException(nameof(format))
        };
    }

    private static string NormalizePath(string entryName)
    {
        var normalized = entryName.Replace('\\', '/');

        // Strip leading ./
        if (normalized.StartsWith("./", StringComparison.Ordinal))
            normalized = normalized[2..];

        // Reject absolute paths
        if (normalized.StartsWith('/') || (normalized.Length >= 2 && normalized[1] == ':'))
            throw new InvalidOperationException(
                $"Absolute path detected in archive entry: '{entryName}'.");

        // Reject path traversal (only actual ".." segments, not filenames containing "..")
        var segments = normalized.Split('/');
        if (Array.Exists(segments, s => s == ".."))
            throw new InvalidOperationException(
                $"Path traversal detected in archive entry: '{entryName}'.");

        return normalized;
    }

    private static bool IsDirectory(string entryName)
    {
        return entryName.EndsWith('/') || entryName.EndsWith('\\');
    }

    // --- ZIP ---

    private static List<ArchiveEntryInfo> ListZipEntries(string archivePath)
    {
        using var zip = ZipFile.OpenRead(archivePath);
        var entries = new List<ArchiveEntryInfo>();

        foreach (var entry in zip.Entries)
        {
            if (IsDirectory(entry.FullName) || entry.FullName.Length == 0)
                continue;

            var normalized = NormalizePath(entry.FullName);
            entries.Add(new ArchiveEntryInfo(normalized, entry.Length, false));
        }

        return entries;
    }

    private static MemoryStream OpenZipEntry(string archivePath, string entryPath)
    {
        using var zip = ZipFile.OpenRead(archivePath);
        var entry = zip.GetEntry(entryPath)
            ?? throw new FileNotFoundException($"Entry not found in archive: '{entryPath}'.");

        ValidateEntrySize(entry.Length, entry.FullName);

        var ms = new MemoryStream((int)Math.Min(entry.Length, int.MaxValue));
        using (var entryStream = entry.Open())
        {
            CopyWithLimit(entryStream, ms, entry.FullName);
        }
        ms.Position = 0;
        return ms;
    }

    private static IEnumerable<(ArchiveEntryInfo Entry, Stream Content)> ReadZipEntries(string archivePath)
    {
        using var zip = ZipFile.OpenRead(archivePath);

        foreach (var entry in zip.Entries)
        {
            if (IsDirectory(entry.FullName) || entry.FullName.Length == 0)
                continue;

            var normalized = NormalizePath(entry.FullName);
            ValidateEntrySize(entry.Length, normalized);
            var info = new ArchiveEntryInfo(normalized, entry.Length, false);

            var ms = new MemoryStream((int)Math.Min(entry.Length, int.MaxValue));
            using (var entryStream = entry.Open())
            {
                CopyWithLimit(entryStream, ms, normalized);
            }
            ms.Position = 0;

            yield return (info, ms);
        }
    }

    // --- TAR / TAR.GZ ---

    private static List<ArchiveEntryInfo> ListTarEntries(string archivePath, bool gzipped)
    {
        using var fs = File.OpenRead(archivePath);
        using var decompressed = gzipped ? new GZipStream(fs, CompressionMode.Decompress) : (Stream)fs;
        using var tar = new TarReader(decompressed);

        var entries = new List<ArchiveEntryInfo>();

        while (tar.GetNextEntry() is { } entry)
        {
            if (entry.EntryType == TarEntryType.Directory)
                continue;

            if (entry.EntryType != TarEntryType.RegularFile
                && entry.EntryType != TarEntryType.V7RegularFile)
                continue;

            var normalized = NormalizePath(entry.Name);
            entries.Add(new ArchiveEntryInfo(normalized, entry.Length, false));
        }

        return entries;
    }

    private static MemoryStream OpenTarEntry(string archivePath, string entryPath, bool gzipped)
    {
        using var fs = File.OpenRead(archivePath);
        using var decompressor = gzipped ? new GZipStream(fs, CompressionMode.Decompress) : null;
        using var tar = new TarReader(decompressor ?? (Stream)fs);

        while (tar.GetNextEntry() is { } entry)
        {
            var normalized = NormalizePath(entry.Name);
            if (string.Equals(normalized, entryPath, StringComparison.Ordinal) && entry.DataStream is not null)
            {
                ValidateEntrySize(entry.Length, normalized);
                var ms = new MemoryStream();
                CopyWithLimit(entry.DataStream, ms, normalized);
                ms.Position = 0;
                return ms;
            }
        }

        throw new FileNotFoundException($"Entry not found in archive: '{entryPath}'.");
    }

    private static IEnumerable<(ArchiveEntryInfo Entry, Stream Content)> ReadTarEntries(
        string archivePath, bool gzipped)
    {
        using var fs = File.OpenRead(archivePath);
        using var decompressed = gzipped ? new GZipStream(fs, CompressionMode.Decompress) : (Stream)fs;
        using var tar = new TarReader(decompressed);

        while (tar.GetNextEntry() is { } entry)
        {
            if (entry.EntryType == TarEntryType.Directory)
                continue;

            if (entry.EntryType != TarEntryType.RegularFile
                && entry.EntryType != TarEntryType.V7RegularFile)
                continue;

            var normalized = NormalizePath(entry.Name);
            ValidateEntrySize(entry.Length, normalized);
            var info = new ArchiveEntryInfo(normalized, entry.Length, false);

            if (entry.DataStream is null)
                continue;

            var ms = new MemoryStream();
            CopyWithLimit(entry.DataStream, ms, normalized);
            ms.Position = 0;

            yield return (info, ms);
        }
    }

    private static void ValidateEntrySize(long declaredSize, string entryName)
    {
        if (declaredSize > MaxEntrySize)
            throw new InvalidOperationException(
                $"Archive entry '{entryName}' exceeds maximum size ({declaredSize} > {MaxEntrySize} bytes).");
    }

    private static void CopyWithLimit(Stream source, MemoryStream destination, string entryName)
    {
        var buffer = new byte[81920];
        long totalRead = 0;
        int bytesRead;

        while ((bytesRead = source.Read(buffer, 0, buffer.Length)) > 0)
        {
            totalRead += bytesRead;
            if (totalRead > MaxEntrySize)
                throw new InvalidOperationException(
                    $"Archive entry '{entryName}' decompressed size exceeds limit ({MaxEntrySize} bytes).");
            destination.Write(buffer, 0, bytesRead);
        }
    }
}
