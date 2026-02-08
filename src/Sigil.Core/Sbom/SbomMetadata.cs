using System.Globalization;

namespace Sigil.Sbom;

public sealed record SbomMetadata(
    SbomFormat Format,
    string SpecVersion,
    string? Name,
    string? Version,
    string? Supplier,
    int ComponentCount)
{
    public string MediaType => Format switch
    {
        SbomFormat.CycloneDx => "application/vnd.cyclonedx+json",
        SbomFormat.Spdx => "application/spdx+json",
        _ => "application/json"
    };

    public Dictionary<string, string> ToDictionary()
    {
        var dict = new Dictionary<string, string>
        {
            ["sbom.format"] = Format == SbomFormat.CycloneDx ? "CycloneDX" : "SPDX",
            ["sbom.specVersion"] = SpecVersion,
            ["sbom.componentCount"] = ComponentCount.ToString(CultureInfo.InvariantCulture)
        };
        if (Name is not null) dict["sbom.name"] = Name;
        if (Version is not null) dict["sbom.version"] = Version;
        if (Supplier is not null) dict["sbom.supplier"] = Supplier;
        return dict;
    }
}
