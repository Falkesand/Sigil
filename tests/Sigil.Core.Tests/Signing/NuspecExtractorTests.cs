using System.IO.Compression;
using Sigil.Signing;

namespace Sigil.Core.Tests.Signing;

public class NuspecExtractorTests : IDisposable
{
    private readonly string _tempDir;

    public NuspecExtractorTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-nuspec-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    [Fact]
    public void TryExtract_ValidNupkg_ExtractsMetadata()
    {
        var nuspec = """
        <?xml version="1.0" encoding="utf-8"?>
        <package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
          <metadata>
            <id>Sigil.Core</id>
            <version>1.0.0</version>
            <authors>Falkesand</authors>
            <description>A distributed trust library</description>
          </metadata>
        </package>
        """;
        var path = CreateNupkg("Sigil.Core.1.0.0.nupkg", nuspec);

        var metadata = NuspecExtractor.TryExtract(path);

        Assert.NotNull(metadata);
        Assert.Equal("Sigil.Core", metadata!["nuget.id"]);
        Assert.Equal("1.0.0", metadata["nuget.version"]);
        Assert.Equal("Falkesand", metadata["nuget.authors"]);
        Assert.Equal("A distributed trust library", metadata["nuget.description"]);
    }

    [Fact]
    public void TryExtract_NonNupkgZip_ReturnsNull()
    {
        var path = CreateZipArchive("notpackage.zip", ("file.txt", "content"));

        var metadata = NuspecExtractor.TryExtract(path);

        Assert.Null(metadata);
    }

    [Fact]
    public void TryExtract_NupkgWithoutNuspec_ReturnsNull()
    {
        var path = CreateZipArchive("missing.nupkg", ("lib/net10.0/lib.dll", "binary"));

        var metadata = NuspecExtractor.TryExtract(path);

        Assert.Null(metadata);
    }

    [Fact]
    public void TryExtract_NuspecWithMissingFields_ReturnsPartialMetadata()
    {
        var nuspec = """
        <?xml version="1.0" encoding="utf-8"?>
        <package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
          <metadata>
            <id>Minimal.Package</id>
            <version>0.1.0</version>
          </metadata>
        </package>
        """;
        var path = CreateNupkg("Minimal.Package.0.1.0.nupkg", nuspec);

        var metadata = NuspecExtractor.TryExtract(path);

        Assert.NotNull(metadata);
        Assert.Equal("Minimal.Package", metadata!["nuget.id"]);
        Assert.Equal("0.1.0", metadata["nuget.version"]);
        Assert.False(metadata.ContainsKey("nuget.authors"));
        Assert.False(metadata.ContainsKey("nuget.description"));
    }

    [Fact]
    public void TryExtract_NuspecWithNoNamespace_ExtractsMetadata()
    {
        var nuspec = """
        <?xml version="1.0" encoding="utf-8"?>
        <package>
          <metadata>
            <id>NoNamespace.Pkg</id>
            <version>2.0.0</version>
            <authors>Test Author</authors>
          </metadata>
        </package>
        """;
        var path = CreateNupkg("NoNamespace.Pkg.2.0.0.nupkg", nuspec);

        var metadata = NuspecExtractor.TryExtract(path);

        Assert.NotNull(metadata);
        Assert.Equal("NoNamespace.Pkg", metadata!["nuget.id"]);
        Assert.Equal("2.0.0", metadata["nuget.version"]);
    }

    [Fact]
    public void TryExtract_InvalidXml_ReturnsNull()
    {
        var path = CreateNupkg("bad.nupkg", "not valid xml <><><>");

        var metadata = NuspecExtractor.TryExtract(path);

        Assert.Null(metadata);
    }

    [Fact]
    public void TryExtract_NuspecInSubdirectory_ExtractsMetadata()
    {
        // Some .nupkg files have the nuspec in a subdirectory
        var nuspec = """
        <?xml version="1.0" encoding="utf-8"?>
        <package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
          <metadata>
            <id>Nested.Package</id>
            <version>3.0.0</version>
          </metadata>
        </package>
        """;
        var path = Path.Combine(_tempDir, "Nested.Package.3.0.0.nupkg");
        using (var fs = File.Create(path))
        using (var zip = new ZipArchive(fs, ZipArchiveMode.Create))
        {
            var entry = zip.CreateEntry("Nested.Package.nuspec");
            using var writer = new StreamWriter(entry.Open());
            writer.Write(nuspec);
        }

        var metadata = NuspecExtractor.TryExtract(path);

        Assert.NotNull(metadata);
        Assert.Equal("Nested.Package", metadata!["nuget.id"]);
    }

    [Fact]
    public void TryExtract_NonExistentFile_ReturnsNull()
    {
        var metadata = NuspecExtractor.TryExtract(Path.Combine(_tempDir, "nope.nupkg"));

        Assert.Null(metadata);
    }

    // --- Helpers ---

    private string CreateNupkg(string name, string nuspecContent)
    {
        var path = Path.Combine(_tempDir, name);
        using var fs = File.Create(path);
        using var zip = new ZipArchive(fs, ZipArchiveMode.Create);
        var nuspecName = Path.GetFileNameWithoutExtension(name);
        // Strip version from nuspec name (e.g., "Sigil.Core.1.0.0" → find ".nuspec")
        var entry = zip.CreateEntry(nuspecName + ".nuspec");
        using var writer = new StreamWriter(entry.Open());
        writer.Write(nuspecContent);
        return path;
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
}
