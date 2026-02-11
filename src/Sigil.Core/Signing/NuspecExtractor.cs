using System.IO.Compression;
using System.Xml;
using System.Xml.Linq;

namespace Sigil.Signing;

/// <summary>
/// Extracts NuGet package metadata from .nupkg files by reading the embedded .nuspec.
/// </summary>
public static class NuspecExtractor
{
    /// <summary>
    /// Tries to extract NuGet metadata from a .nupkg archive.
    /// Returns null if the file is not a .nupkg, has no .nuspec, or parsing fails.
    /// </summary>
    public static Dictionary<string, string>? TryExtract(string archivePath)
    {
        if (archivePath is null)
            return null;

        if (!archivePath.EndsWith(".nupkg", StringComparison.OrdinalIgnoreCase))
            return null;

        if (!File.Exists(archivePath))
            return null;

        try
        {
            using var zip = ZipFile.OpenRead(archivePath);

            // Find the .nuspec entry
            var nuspecEntry = zip.Entries
                .FirstOrDefault(e => e.FullName.EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase));

            if (nuspecEntry is null)
                return null;

            using var stream = nuspecEntry.Open();

            // Secure XML parsing: prohibit DTD processing and external entities (XXE protection)
            var readerSettings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersFromEntities = 1024,
                MaxCharactersInDocument = 10 * 1024 * 1024
            };
            using var xmlReader = XmlReader.Create(stream, readerSettings);
            var doc = XDocument.Load(xmlReader);

            var root = doc.Root;
            if (root is null)
                return null;

            // Handle both namespaced and non-namespaced nuspec
            var ns = root.GetDefaultNamespace();
            var metadata = root.Element(ns + "metadata");
            if (metadata is null)
                return null;

            var result = new Dictionary<string, string>();

            var id = metadata.Element(ns + "id")?.Value;
            if (id is not null)
                result["nuget.id"] = id;

            var version = metadata.Element(ns + "version")?.Value;
            if (version is not null)
                result["nuget.version"] = version;

            var authors = metadata.Element(ns + "authors")?.Value;
            if (authors is not null)
                result["nuget.authors"] = authors;

            var description = metadata.Element(ns + "description")?.Value;
            if (description is not null)
                result["nuget.description"] = description;

            return result.Count > 0 ? result : null;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return null;
        }
    }
}
