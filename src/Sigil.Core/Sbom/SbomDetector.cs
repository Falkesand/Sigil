using System.Text.Json;

namespace Sigil.Sbom;

/// <summary>
/// Detects SBOM format from file bytes. Returns null for non-SBOM or invalid files.
/// Never throws — any failure returns null.
/// </summary>
public static class SbomDetector
{
    public static SbomMetadata? TryDetect(byte[] fileBytes)
    {
        if (fileBytes is null || fileBytes.Length == 0)
            return null;

        try
        {
            using var doc = JsonDocument.Parse(fileBytes);
            var root = doc.RootElement;

            return CycloneDxParser.TryParse(root) ?? SpdxParser.TryParse(root);
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
