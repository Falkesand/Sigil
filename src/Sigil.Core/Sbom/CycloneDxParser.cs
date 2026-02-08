using System.Text.Json;

namespace Sigil.Sbom;

/// <summary>
/// Parses CycloneDX JSON SBOMs. Returns null if the document is not CycloneDX.
/// </summary>
public static class CycloneDxParser
{
    public static SbomMetadata? TryParse(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object)
            return null;

        if (!root.TryGetProperty("bomFormat", out var bomFormatElement))
            return null;

        var bomFormat = bomFormatElement.GetString();
        if (bomFormat is null || !bomFormat.Equals("CycloneDX", StringComparison.OrdinalIgnoreCase))
            return null;

        var specVersion = root.TryGetProperty("specVersion", out var sv) ? sv.GetString() ?? "" : "";

        string? name = null;
        string? version = null;
        string? supplier = null;

        if (root.TryGetProperty("metadata", out var metadata) &&
            metadata.TryGetProperty("component", out var component))
        {
            name = component.TryGetProperty("name", out var n) ? n.GetString() : null;
            version = component.TryGetProperty("version", out var v) ? v.GetString() : null;

            if (component.TryGetProperty("supplier", out var sup) &&
                sup.TryGetProperty("name", out var supName))
            {
                supplier = supName.GetString();
            }
        }

        int componentCount = 0;
        if (root.TryGetProperty("components", out var components) &&
            components.ValueKind == JsonValueKind.Array)
        {
            componentCount = components.GetArrayLength();
        }

        return new SbomMetadata(SbomFormat.CycloneDx, specVersion, name, version, supplier, componentCount);
    }
}
