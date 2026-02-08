using Sigil.Attestation;

namespace Sigil.Core.Tests.Attestation;

public class PredicateTypeRegistryTests
{
    [Theory]
    [InlineData("slsa-provenance-v1", "https://slsa.dev/provenance/v1")]
    [InlineData("spdx-json", "https://spdx.dev/Document")]
    [InlineData("cyclonedx", "https://cyclonedx.org/bom")]
    public void Resolve_known_short_name_returns_uri(string shortName, string expectedUri)
    {
        var resolved = PredicateTypeRegistry.Resolve(shortName);

        Assert.Equal(expectedUri, resolved);
    }

    [Fact]
    public void Resolve_known_short_name_is_case_insensitive()
    {
        var result = PredicateTypeRegistry.Resolve("SLSA-Provenance-V1");

        Assert.Equal("https://slsa.dev/provenance/v1", result);
    }

    [Fact]
    public void Resolve_valid_uri_passes_through()
    {
        var customUri = "https://example.com/my-predicate/v1";

        var result = PredicateTypeRegistry.Resolve(customUri);

        Assert.Equal(customUri, result);
    }

    [Fact]
    public void Resolve_http_uri_passes_through()
    {
        var httpUri = "http://example.com/predicate";

        var result = PredicateTypeRegistry.Resolve(httpUri);

        Assert.Equal(httpUri, result);
    }

    [Fact]
    public void Resolve_invalid_string_throws()
    {
        Assert.Throws<ArgumentException>(() =>
            PredicateTypeRegistry.Resolve("not-a-known-type"));
    }

    [Fact]
    public void Resolve_empty_throws()
    {
        Assert.Throws<ArgumentException>(() =>
            PredicateTypeRegistry.Resolve(""));
    }

    [Fact]
    public void Resolve_whitespace_throws()
    {
        Assert.Throws<ArgumentException>(() =>
            PredicateTypeRegistry.Resolve("   "));
    }

    [Fact]
    public void GetKnownTypes_returns_all_entries()
    {
        var known = PredicateTypeRegistry.GetKnownTypes();

        Assert.Equal(3, known.Count);
        Assert.True(known.ContainsKey("slsa-provenance-v1"));
        Assert.True(known.ContainsKey("spdx-json"));
        Assert.True(known.ContainsKey("cyclonedx"));
    }
}
