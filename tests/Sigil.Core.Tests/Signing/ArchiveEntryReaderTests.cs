using System.Formats.Tar;
using System.IO.Compression;
using Sigil.Signing;

namespace Sigil.Core.Tests.Signing;

public class ArchiveEntryReaderTests : IDisposable
{
    private readonly string _tempDir;

    public ArchiveEntryReaderTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-archread-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    [Fact]
    public void ListEntries_Zip_ReturnsAllFiles()
    {
        var path = CreateZipArchive("list.zip",
            ("a.txt", "aaa"),
            ("b.txt", "bbb"),
            ("sub/c.txt", "ccc"));

        var entries = ArchiveEntryReader.ListEntries(path, ArchiveFormat.Zip);

        Assert.Equal(3, entries.Count);
        Assert.Contains(entries, e => e.RelativePath == "a.txt");
        Assert.Contains(entries, e => e.RelativePath == "b.txt");
        Assert.Contains(entries, e => e.RelativePath == "sub/c.txt");
        Assert.All(entries, e => Assert.False(e.IsDirectory));
    }

    [Fact]
    public void ListEntries_TarGz_ReturnsAllFiles()
    {
        var path = CreateTarGzArchive("list.tar.gz",
            ("x.txt", "xxx"),
            ("y.txt", "yyy"));

        var entries = ArchiveEntryReader.ListEntries(path, ArchiveFormat.TarGz);

        Assert.Equal(2, entries.Count);
        Assert.Contains(entries, e => e.RelativePath == "x.txt");
        Assert.Contains(entries, e => e.RelativePath == "y.txt");
    }

    [Fact]
    public void ListEntries_Tar_ReturnsAllFiles()
    {
        var path = CreateTarArchive("list.tar",
            ("one.txt", "111"),
            ("two.txt", "222"));

        var entries = ArchiveEntryReader.ListEntries(path, ArchiveFormat.Tar);

        Assert.Equal(2, entries.Count);
    }

    [Fact]
    public void ListEntries_SkipsDirectories()
    {
        var path = CreateZipWithDirectory("withdir.zip");

        var entries = ArchiveEntryReader.ListEntries(path, ArchiveFormat.Zip);

        Assert.All(entries, e => Assert.False(e.IsDirectory));
        Assert.Single(entries);
    }

    [Fact]
    public void ListEntries_NormalizesPathSeparators()
    {
        var path = CreateZipArchive("paths.zip",
            ("folder/file.txt", "content"));

        var entries = ArchiveEntryReader.ListEntries(path, ArchiveFormat.Zip);

        Assert.Single(entries);
        Assert.Equal("folder/file.txt", entries[0].RelativePath);
        Assert.DoesNotContain("\\", entries[0].RelativePath);
    }

    [Fact]
    public void ListEntries_StripsDotSlashPrefix()
    {
        var path = CreateTarArchiveWithPrefixedPaths("prefix.tar");

        var entries = ArchiveEntryReader.ListEntries(path, ArchiveFormat.Tar);

        Assert.All(entries, e => Assert.False(e.RelativePath.StartsWith("./", StringComparison.Ordinal)));
    }

    [Fact]
    public void ListEntries_RejectsPathTraversal()
    {
        var path = CreateZipArchive("traversal.zip",
            ("../../../etc/passwd", "evil"));

        Assert.Throws<InvalidOperationException>(
            () => ArchiveEntryReader.ListEntries(path, ArchiveFormat.Zip));
    }

    [Fact]
    public void OpenEntry_ReturnsCorrectContent()
    {
        var path = CreateZipArchive("open.zip",
            ("readme.txt", "Hello, World!"));

        using var stream = ArchiveEntryReader.OpenEntry(path, ArchiveFormat.Zip, "readme.txt");
        using var reader = new StreamReader(stream);
        var content = reader.ReadToEnd();

        Assert.Equal("Hello, World!", content);
    }

    [Fact]
    public void ReadEntries_Zip_YieldsAllEntriesWithContent()
    {
        var path = CreateZipArchive("read.zip",
            ("p.txt", "ppp"),
            ("q.txt", "qqq"));

        var results = new List<(string Path, string Content)>();
        foreach (var (entry, content) in ArchiveEntryReader.ReadEntries(path, ArchiveFormat.Zip))
        {
            using var reader = new StreamReader(content);
            results.Add((entry.RelativePath, reader.ReadToEnd()));
        }

        Assert.Equal(2, results.Count);
        Assert.Contains(results, r => r.Path == "p.txt" && r.Content == "ppp");
        Assert.Contains(results, r => r.Path == "q.txt" && r.Content == "qqq");
    }

    [Fact]
    public void ReadEntries_TarGz_YieldsAllEntriesWithContent()
    {
        var path = CreateTarGzArchive("read.tar.gz",
            ("m.txt", "mmm"));

        var results = new List<(string Path, string Content)>();
        foreach (var (entry, content) in ArchiveEntryReader.ReadEntries(path, ArchiveFormat.TarGz))
        {
            using var reader = new StreamReader(content);
            results.Add((entry.RelativePath, reader.ReadToEnd()));
        }

        Assert.Single(results);
        Assert.Equal("m.txt", results[0].Path);
        Assert.Equal("mmm", results[0].Content);
    }

    private string CreateZipArchive(string name, params (string entryName, string content)[] entries)
    {
        var path = Path.Combine(_tempDir, name);
        using var fs = File.Create(path);
        using var zip = new ZipArchive(fs, ZipArchiveMode.Create);
        foreach (var (entryName, content) in entries)
        {
            var entry = zip.CreateEntry(entryName);
            using var writer = new StreamWriter(entry.Open());
            writer.Write(content);
        }
        return path;
    }

    private string CreateZipWithDirectory(string name)
    {
        var path = Path.Combine(_tempDir, name);
        using var fs = File.Create(path);
        using var zip = new ZipArchive(fs, ZipArchiveMode.Create);
        // Create a directory entry (trailing slash)
        zip.CreateEntry("mydir/");
        // Create a file inside the directory
        var entry = zip.CreateEntry("mydir/file.txt");
        using var writer = new StreamWriter(entry.Open());
        writer.Write("in dir");
        return path;
    }

    private string CreateTarGzArchive(string name, params (string entryName, string content)[] entries)
    {
        var path = Path.Combine(_tempDir, name);
        using var fs = File.Create(path);
        using var gz = new GZipStream(fs, CompressionLevel.Optimal);
        using var tar = new TarWriter(gz, TarEntryFormat.Pax);
        foreach (var (entryName, content) in entries)
        {
            var bytes = System.Text.Encoding.UTF8.GetBytes(content);
            var entry = new PaxTarEntry(TarEntryType.RegularFile, entryName)
            {
                DataStream = new MemoryStream(bytes)
            };
            tar.WriteEntry(entry);
        }
        return path;
    }

    private string CreateTarArchive(string name, params (string entryName, string content)[] entries)
    {
        var path = Path.Combine(_tempDir, name);
        using var fs = File.Create(path);
        using var tar = new TarWriter(fs, TarEntryFormat.Pax);
        foreach (var (entryName, content) in entries)
        {
            var bytes = System.Text.Encoding.UTF8.GetBytes(content);
            var entry = new PaxTarEntry(TarEntryType.RegularFile, entryName)
            {
                DataStream = new MemoryStream(bytes)
            };
            tar.WriteEntry(entry);
        }
        return path;
    }

    private string CreateTarArchiveWithPrefixedPaths(string name)
    {
        var path = Path.Combine(_tempDir, name);
        using var fs = File.Create(path);
        using var tar = new TarWriter(fs, TarEntryFormat.Pax);
        var bytes = System.Text.Encoding.UTF8.GetBytes("content");
        var entry = new PaxTarEntry(TarEntryType.RegularFile, "./prefixed.txt")
        {
            DataStream = new MemoryStream(bytes)
        };
        tar.WriteEntry(entry);
        return path;
    }
}
