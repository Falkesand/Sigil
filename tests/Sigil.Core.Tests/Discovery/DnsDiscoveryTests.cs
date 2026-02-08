using Sigil.Discovery;

namespace Sigil.Core.Tests.Discovery;

public class DnsDiscoveryTests
{
    [Fact]
    public void ParseSigilRecord_extracts_bundle_url()
    {
        var record = "v=sigil1 bundle=https://example.com/.well-known/sigil/trust.json";

        var result = DnsDiscovery.ParseSigilRecord(record);

        Assert.True(result.IsSuccess);
        Assert.Equal("https://example.com/.well-known/sigil/trust.json", result.Value);
    }

    [Fact]
    public void ParseSigilRecord_rejects_wrong_version()
    {
        var record = "v=sigil2 bundle=https://example.com/trust.json";

        var result = DnsDiscovery.ParseSigilRecord(record);

        Assert.False(result.IsSuccess);
        Assert.Equal(DiscoveryErrorKind.DnsError, result.ErrorKind);
        Assert.Contains("version", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ParseSigilRecord_rejects_missing_version()
    {
        var record = "bundle=https://example.com/trust.json";

        var result = DnsDiscovery.ParseSigilRecord(record);

        Assert.False(result.IsSuccess);
        Assert.Equal(DiscoveryErrorKind.DnsError, result.ErrorKind);
    }

    [Fact]
    public void ParseSigilRecord_rejects_missing_bundle_key()
    {
        var record = "v=sigil1 other=value";

        var result = DnsDiscovery.ParseSigilRecord(record);

        Assert.False(result.IsSuccess);
        Assert.Equal(DiscoveryErrorKind.DnsError, result.ErrorKind);
        Assert.Contains("bundle", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ParseSigilRecord_handles_extra_whitespace()
    {
        var record = "v=sigil1  bundle=https://example.com/trust.json  extra=ignored";

        var result = DnsDiscovery.ParseSigilRecord(record);

        Assert.True(result.IsSuccess);
        Assert.Equal("https://example.com/trust.json", result.Value);
    }

    [Fact]
    public void ParseSigilRecord_rejects_empty_string()
    {
        var result = DnsDiscovery.ParseSigilRecord("");

        Assert.False(result.IsSuccess);
        Assert.Equal(DiscoveryErrorKind.DnsError, result.ErrorKind);
    }

    [Fact]
    public void FindSigilRecord_finds_first_matching_record()
    {
        var records = new List<string>
        {
            "some other record",
            "v=sigil1 bundle=https://example.com/trust.json",
            "v=sigil1 bundle=https://fallback.example.com/trust.json"
        };

        var result = DnsDiscovery.FindSigilRecord(records);

        Assert.True(result.IsSuccess);
        Assert.Equal("https://example.com/trust.json", result.Value);
    }

    [Fact]
    public void FindSigilRecord_returns_NotFound_when_no_sigil_records()
    {
        var records = new List<string>
        {
            "v=spf1 include:example.com",
            "google-site-verification=abc123"
        };

        var result = DnsDiscovery.FindSigilRecord(records);

        Assert.False(result.IsSuccess);
        Assert.Equal(DiscoveryErrorKind.NotFound, result.ErrorKind);
    }

    [Fact]
    public void FindSigilRecord_returns_NotFound_for_empty_list()
    {
        var result = DnsDiscovery.FindSigilRecord(new List<string>());

        Assert.False(result.IsSuccess);
        Assert.Equal(DiscoveryErrorKind.NotFound, result.ErrorKind);
    }
}
