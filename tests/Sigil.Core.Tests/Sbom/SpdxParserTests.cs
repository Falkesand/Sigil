using System.Text.Json;
using Sigil.Sbom;

namespace Sigil.Core.Tests.Sbom;

public class SpdxParserTests
{
    [Fact]
    public void TryParse_FullSpdx_ReturnsMetadata()
    {
        var json = """
        {
            "spdxVersion": "SPDX-2.3",
            "name": "my-spdx-doc",
            "documentNamespace": "https://example.com/ns",
            "packages": [
                { "name": "main-pkg", "versionInfo": "1.2.3", "supplier": "Organization: Acme Inc" },
                { "name": "dep-pkg" }
            ]
        }
        """;
        using var doc = JsonDocument.Parse(json);
        var result = SpdxParser.TryParse(doc.RootElement);

        Assert.NotNull(result);
        Assert.Equal(SbomFormat.Spdx, result.Format);
        Assert.Equal("SPDX-2.3", result.SpecVersion);
        Assert.Equal("my-spdx-doc", result.Name);
        Assert.Equal("1.2.3", result.Version);
        Assert.Equal("Acme Inc", result.Supplier);
        Assert.Equal(2, result.ComponentCount);
        Assert.Equal("https://example.com/ns", result.SerialNumber);
    }

    [Fact]
    public void TryParse_MinimalSpdx_ReturnsMetadata()
    {
        var json = """
        {
            "spdxVersion": "SPDX-2.3"
        }
        """;
        using var doc = JsonDocument.Parse(json);
        var result = SpdxParser.TryParse(doc.RootElement);

        Assert.NotNull(result);
        Assert.Equal(SbomFormat.Spdx, result.Format);
        Assert.Equal("SPDX-2.3", result.SpecVersion);
        Assert.Null(result.Name);
        Assert.Null(result.Version);
        Assert.Null(result.Supplier);
        Assert.Equal(0, result.ComponentCount);
        Assert.Null(result.SerialNumber);
    }

    [Fact]
    public void TryParse_CaseInsensitiveSpdxVersion()
    {
        var json = """
        {
            "spdxVersion": "spdx-2.3"
        }
        """;
        using var doc = JsonDocument.Parse(json);
        var result = SpdxParser.TryParse(doc.RootElement);

        Assert.NotNull(result);
        Assert.Equal(SbomFormat.Spdx, result.Format);
    }

    [Fact]
    public void TryParse_NotSpdx_ReturnsNull()
    {
        var json = """{ "foo": "bar" }""";
        using var doc = JsonDocument.Parse(json);
        Assert.Null(SpdxParser.TryParse(doc.RootElement));
    }

    [Fact]
    public void TryParse_SupplierWithOrganizationPrefix_StripsPrefix()
    {
        var json = """
        {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                { "name": "pkg", "supplier": "Organization: My Company LLC" }
            ]
        }
        """;
        using var doc = JsonDocument.Parse(json);
        var result = SpdxParser.TryParse(doc.RootElement);

        Assert.NotNull(result);
        Assert.Equal("My Company LLC", result.Supplier);
    }

    [Fact]
    public void TryParse_SupplierWithPersonPrefix_StripsPrefix()
    {
        var json = """
        {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                { "name": "pkg", "supplier": "Person: John Doe" }
            ]
        }
        """;
        using var doc = JsonDocument.Parse(json);
        var result = SpdxParser.TryParse(doc.RootElement);

        Assert.NotNull(result);
        Assert.Equal("John Doe", result.Supplier);
    }
}
