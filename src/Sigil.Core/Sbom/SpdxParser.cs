using System.Text.Json;

namespace Sigil.Sbom;

/// <summary>
/// Parses SPDX 2.3 JSON SBOMs. Returns null if the document is not SPDX.
/// </summary>
public static class SpdxParser
{
    public static SbomMetadata? TryParse(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object)
            return null;

        if (!root.TryGetProperty("spdxVersion", out var spdxVersionElement))
            return null;

        var spdxVersion = spdxVersionElement.GetString();
        if (spdxVersion is null || !spdxVersion.StartsWith("SPDX-", StringComparison.OrdinalIgnoreCase))
            return null;

        string? name = root.TryGetProperty("name", out var n) ? n.GetString() : null;
        var serialNumber = root.TryGetProperty("documentNamespace", out var dns) ? dns.GetString() : null;
        string? version = null;
        string? supplier = null;
        int componentCount = 0;

        if (root.TryGetProperty("packages", out var packages) &&
            packages.ValueKind == JsonValueKind.Array)
        {
            componentCount = packages.GetArrayLength();

            // Extract metadata from the first package
            if (componentCount > 0)
            {
                var firstPkg = packages[0];
                version = firstPkg.TryGetProperty("versionInfo", out var v) ? v.GetString() : null;

                if (firstPkg.TryGetProperty("supplier", out var sup))
                {
                    supplier = StripActorPrefix(sup.GetString());
                }
            }
        }

        return new SbomMetadata(SbomFormat.Spdx, spdxVersion, name, version, supplier, componentCount, serialNumber);
    }

    private static string? StripActorPrefix(string? value)
    {
        if (value is null)
            return null;

        // SPDX supplier format: "Organization: Name" or "Person: Name"
        var colonIndex = value.IndexOf(": ", StringComparison.Ordinal);
        if (colonIndex >= 0)
            return value[(colonIndex + 2)..];

        return value;
    }
}
