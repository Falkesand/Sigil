namespace Sigil.Attestation;

public static class PredicateTypeRegistry
{
    private static readonly Dictionary<string, string> KnownTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        ["slsa-provenance-v1"] = "https://slsa.dev/provenance/v1",
        ["spdx-json"] = "https://spdx.dev/Document",
        ["cyclonedx"] = "https://cyclonedx.org/bom"
    };

    public static string Resolve(string typeOrShortName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(typeOrShortName);

        if (KnownTypes.TryGetValue(typeOrShortName, out var uri))
            return uri;

        if (Uri.TryCreate(typeOrShortName, UriKind.Absolute, out var parsed)
            && (parsed.Scheme == "https" || parsed.Scheme == "http"))
            return typeOrShortName;

        throw new ArgumentException($"Unknown predicate type: '{typeOrShortName}'. " +
            "Use a known short name (slsa-provenance-v1, spdx-json, cyclonedx) or a valid URI.",
            nameof(typeOrShortName));
    }

    public static IReadOnlyDictionary<string, string> GetKnownTypes() => KnownTypes;
}
