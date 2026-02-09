using System.Text;
using System.Text.Json;
using Sigil.Sbom;

namespace Sigil.Core.Tests.Sbom;

public class SbomDetectorTests
{
    [Fact]
    public void SbomMetadata_ToDictionary_ProducesExpectedKeys()
    {
        var metadata = new SbomMetadata(
            SbomFormat.CycloneDx,
            "1.6",
            "my-app",
            "2.1.0",
            "Acme Corp",
            42,
            "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79");

        var dict = metadata.ToDictionary();

        Assert.Equal("CycloneDX", dict["sbom.format"]);
        Assert.Equal("1.6", dict["sbom.specVersion"]);
        Assert.Equal("my-app", dict["sbom.name"]);
        Assert.Equal("2.1.0", dict["sbom.version"]);
        Assert.Equal("Acme Corp", dict["sbom.supplier"]);
        Assert.Equal("42", dict["sbom.componentCount"]);
        Assert.Equal("urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79", dict["sbom.serialNumber"]);
    }

    [Fact]
    public void SbomMetadata_ToDictionary_OmitsNullOptionalFields()
    {
        var metadata = new SbomMetadata(
            SbomFormat.Spdx,
            "SPDX-2.3",
            null,
            null,
            null,
            10,
            null);

        var dict = metadata.ToDictionary();

        Assert.Equal("SPDX", dict["sbom.format"]);
        Assert.Equal("SPDX-2.3", dict["sbom.specVersion"]);
        Assert.Equal("10", dict["sbom.componentCount"]);
        Assert.False(dict.ContainsKey("sbom.name"));
        Assert.False(dict.ContainsKey("sbom.version"));
        Assert.False(dict.ContainsKey("sbom.supplier"));
        Assert.False(dict.ContainsKey("sbom.serialNumber"));
    }

    [Fact]
    public void SbomMetadata_MediaType_CycloneDx()
    {
        var metadata = new SbomMetadata(SbomFormat.CycloneDx, "1.6", null, null, null, 0, null);
        Assert.Equal("application/vnd.cyclonedx+json", metadata.MediaType);
    }

    [Fact]
    public void SbomMetadata_MediaType_Spdx()
    {
        var metadata = new SbomMetadata(SbomFormat.Spdx, "SPDX-2.3", null, null, null, 0, null);
        Assert.Equal("application/spdx+json", metadata.MediaType);
    }

    [Fact]
    public void TryDetect_CycloneDx_ReturnsMetadata()
    {
        var json = """
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:12345678-1234-1234-1234-123456789abc",
            "metadata": {
                "component": {
                    "name": "my-app",
                    "version": "1.0.0",
                    "supplier": { "name": "Acme" }
                }
            },
            "components": [
                { "name": "lib-a" },
                { "name": "lib-b" }
            ]
        }
        """;
        var bytes = Encoding.UTF8.GetBytes(json);

        var result = SbomDetector.TryDetect(bytes);

        Assert.NotNull(result);
        Assert.Equal(SbomFormat.CycloneDx, result.Format);
        Assert.Equal("1.6", result.SpecVersion);
        Assert.Equal("my-app", result.Name);
        Assert.Equal("1.0.0", result.Version);
        Assert.Equal("Acme", result.Supplier);
        Assert.Equal(2, result.ComponentCount);
        Assert.Equal("urn:uuid:12345678-1234-1234-1234-123456789abc", result.SerialNumber);
    }

    [Fact]
    public void TryDetect_Spdx_ReturnsMetadata()
    {
        var json = """
        {
            "spdxVersion": "SPDX-2.3",
            "name": "my-document",
            "documentNamespace": "https://example.com/doc",
            "packages": [
                { "name": "pkg-a", "versionInfo": "3.0.0", "supplier": "Organization: Acme Inc" },
                { "name": "pkg-b" }
            ]
        }
        """;
        var bytes = Encoding.UTF8.GetBytes(json);

        var result = SbomDetector.TryDetect(bytes);

        Assert.NotNull(result);
        Assert.Equal(SbomFormat.Spdx, result.Format);
        Assert.Equal("SPDX-2.3", result.SpecVersion);
        Assert.Equal("my-document", result.Name);
        Assert.Equal("3.0.0", result.Version);
        Assert.Equal("Acme Inc", result.Supplier);
        Assert.Equal(2, result.ComponentCount);
        Assert.Equal("https://example.com/doc", result.SerialNumber);
    }

    [Fact]
    public void TryDetect_NonSbomJson_ReturnsNull()
    {
        var json = """{ "foo": "bar" }"""u8.ToArray();
        Assert.Null(SbomDetector.TryDetect(json));
    }

    [Fact]
    public void TryDetect_InvalidJson_ReturnsNull()
    {
        var bytes = "not valid json at all"u8.ToArray();
        Assert.Null(SbomDetector.TryDetect(bytes));
    }

    [Fact]
    public void TryDetect_BinaryFile_ReturnsNull()
    {
        var bytes = new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }; // PNG header
        Assert.Null(SbomDetector.TryDetect(bytes));
    }

    [Fact]
    public void TryDetect_EmptyInput_ReturnsNull()
    {
        Assert.Null(SbomDetector.TryDetect([]));
    }

    [Fact]
    public void TryDetect_NullInput_ReturnsNull()
    {
        Assert.Null(SbomDetector.TryDetect(null!));
    }
}
