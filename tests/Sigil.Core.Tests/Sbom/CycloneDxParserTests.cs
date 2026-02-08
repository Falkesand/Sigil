using System.Text.Json;
using Sigil.Sbom;

namespace Sigil.Core.Tests.Sbom;

public class CycloneDxParserTests
{
    [Fact]
    public void TryParse_FullCycloneDx_ReturnsMetadata()
    {
        var json = """
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {
                "component": {
                    "name": "my-app",
                    "version": "2.0.0",
                    "supplier": { "name": "Acme Corp" }
                }
            },
            "components": [
                { "name": "lib-a" },
                { "name": "lib-b" },
                { "name": "lib-c" }
            ]
        }
        """;
        using var doc = JsonDocument.Parse(json);
        var result = CycloneDxParser.TryParse(doc.RootElement);

        Assert.NotNull(result);
        Assert.Equal(SbomFormat.CycloneDx, result.Format);
        Assert.Equal("1.6", result.SpecVersion);
        Assert.Equal("my-app", result.Name);
        Assert.Equal("2.0.0", result.Version);
        Assert.Equal("Acme Corp", result.Supplier);
        Assert.Equal(3, result.ComponentCount);
    }

    [Fact]
    public void TryParse_MinimalCycloneDx_ReturnsMetadata()
    {
        var json = """
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5"
        }
        """;
        using var doc = JsonDocument.Parse(json);
        var result = CycloneDxParser.TryParse(doc.RootElement);

        Assert.NotNull(result);
        Assert.Equal(SbomFormat.CycloneDx, result.Format);
        Assert.Equal("1.5", result.SpecVersion);
        Assert.Null(result.Name);
        Assert.Null(result.Version);
        Assert.Null(result.Supplier);
        Assert.Equal(0, result.ComponentCount);
    }

    [Fact]
    public void TryParse_CaseInsensitiveBomFormat()
    {
        var json = """
        {
            "bomFormat": "cyclonedx",
            "specVersion": "1.4"
        }
        """;
        using var doc = JsonDocument.Parse(json);
        var result = CycloneDxParser.TryParse(doc.RootElement);

        Assert.NotNull(result);
        Assert.Equal(SbomFormat.CycloneDx, result.Format);
    }

    [Fact]
    public void TryParse_NotCycloneDx_ReturnsNull()
    {
        var json = """{ "foo": "bar" }""";
        using var doc = JsonDocument.Parse(json);
        Assert.Null(CycloneDxParser.TryParse(doc.RootElement));
    }

    [Fact]
    public void TryParse_WrongBomFormat_ReturnsNull()
    {
        var json = """
        {
            "bomFormat": "SomeOtherFormat",
            "specVersion": "1.0"
        }
        """;
        using var doc = JsonDocument.Parse(json);
        Assert.Null(CycloneDxParser.TryParse(doc.RootElement));
    }
}
