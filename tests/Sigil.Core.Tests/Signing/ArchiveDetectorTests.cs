using System.Formats.Tar;
using System.IO.Compression;
using Sigil.Signing;

namespace Sigil.Core.Tests.Signing;

public class ArchiveDetectorTests : IDisposable
{
    private readonly string _tempDir;

    public ArchiveDetectorTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-archdet-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    [Fact]
    public void Detect_ZipByMagicBytes_ReturnsZip()
    {
        var path = CreateZipArchive("test.zip", ("file.txt", "hello"));
        Assert.Equal(ArchiveFormat.Zip, ArchiveDetector.Detect(path));
    }

    [Fact]
    public void Detect_TarGzByMagicBytes_ReturnsTarGz()
    {
        var path = CreateTarGzArchive("test.tar.gz", ("file.txt", "hello"));
        Assert.Equal(ArchiveFormat.TarGz, ArchiveDetector.Detect(path));
    }

    [Fact]
    public void Detect_TarByHeader_ReturnsTar()
    {
        var path = CreateTarArchive("test.tar", ("file.txt", "hello"));
        Assert.Equal(ArchiveFormat.Tar, ArchiveDetector.Detect(path));
    }

    [Fact]
    public void Detect_NupkgByExtension_ReturnsZip()
    {
        var path = CreateZipArchive("package.nupkg", ("lib/net10.0/lib.dll", "binary"));
        Assert.Equal(ArchiveFormat.Zip, ArchiveDetector.Detect(path));
    }

    [Fact]
    public void Detect_TgzByExtension_ReturnsTarGz()
    {
        var path = CreateTarGzArchive("archive.tgz", ("file.txt", "hello"));
        Assert.Equal(ArchiveFormat.TarGz, ArchiveDetector.Detect(path));
    }

    [Fact]
    public void Detect_UnknownFile_ReturnsNull()
    {
        var path = Path.Combine(_tempDir, "readme.txt");
        File.WriteAllText(path, "This is not an archive");
        Assert.Null(ArchiveDetector.Detect(path));
    }

    [Fact]
    public void Detect_EmptyFile_ReturnsNull()
    {
        var path = Path.Combine(_tempDir, "empty.bin");
        File.WriteAllBytes(path, []);
        Assert.Null(ArchiveDetector.Detect(path));
    }

    [Fact]
    public void Detect_Stream_ZipMagicBytes_ReturnsZip()
    {
        var path = CreateZipArchive("stream.zip", ("a.txt", "content"));
        using var stream = File.OpenRead(path);
        Assert.Equal(ArchiveFormat.Zip, ArchiveDetector.Detect(stream, "stream.zip"));
    }

    [Fact]
    public void Detect_Stream_NullFileName_DetectsByContent()
    {
        var path = CreateZipArchive("noname.zip", ("b.txt", "data"));
        using var stream = File.OpenRead(path);
        Assert.Equal(ArchiveFormat.Zip, ArchiveDetector.Detect(stream, null));
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
}
