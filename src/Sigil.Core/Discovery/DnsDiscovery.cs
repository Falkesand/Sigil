namespace Sigil.Discovery;

/// <summary>
/// Resolves trust bundles via DNS TXT records at _sigil.domain.
/// Record format: "v=sigil1 bundle=https://example.com/.well-known/sigil/trust.json"
/// </summary>
public sealed class DnsDiscovery : IDiscoveryResolver
{
    private const string RecordPrefix = "_sigil.";
    private const string RequiredVersion = "sigil1";

    private readonly WellKnownResolver _wellKnownResolver;

    public DnsDiscovery(WellKnownResolver wellKnownResolver)
    {
        ArgumentNullException.ThrowIfNull(wellKnownResolver);
        _wellKnownResolver = wellKnownResolver;
    }

    public DnsDiscovery() : this(new WellKnownResolver())
    {
    }

    public async Task<DiscoveryResult<string>> ResolveAsync(
        string identifier,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(identifier);

        var dnsName = RecordPrefix + identifier;

        var queryResult = await DnsTxtClient.QueryAsync(dnsName, cancellationToken).ConfigureAwait(false);
        if (!queryResult.IsSuccess)
        {
            return DiscoveryResult<string>.Fail(queryResult.ErrorKind, queryResult.ErrorMessage);
        }

        var findResult = FindSigilRecord(queryResult.Value);
        if (!findResult.IsSuccess)
        {
            return DiscoveryResult<string>.Fail(findResult.ErrorKind, findResult.ErrorMessage);
        }

        // Fetch the bundle from the URL found in the DNS record
        return await _wellKnownResolver.ResolveAsync(findResult.Value, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Parses a single TXT record in Sigil format.
    /// Returns the bundle URL if valid, or an error.
    /// </summary>
    public static DiscoveryResult<string> ParseSigilRecord(string record)
    {
        if (string.IsNullOrWhiteSpace(record))
        {
            return DiscoveryResult<string>.Fail(DiscoveryErrorKind.DnsError,
                "DNS TXT record is empty.");
        }

        var pairs = ParseKeyValuePairs(record);

        if (!pairs.TryGetValue("v", out var version) ||
            !string.Equals(version, RequiredVersion, StringComparison.Ordinal))
        {
            return DiscoveryResult<string>.Fail(DiscoveryErrorKind.DnsError,
                $"Unsupported or missing version. Expected v={RequiredVersion}");
        }

        if (!pairs.TryGetValue("bundle", out var bundleUrl) ||
            string.IsNullOrWhiteSpace(bundleUrl))
        {
            return DiscoveryResult<string>.Fail(DiscoveryErrorKind.DnsError,
                "Missing 'bundle' key in DNS TXT record.");
        }

        return DiscoveryResult<string>.Ok(bundleUrl);
    }

    /// <summary>
    /// Searches a list of TXT records for the first valid Sigil record.
    /// </summary>
    public static DiscoveryResult<string> FindSigilRecord(IReadOnlyList<string> records)
    {
        foreach (var record in records)
        {
            var result = ParseSigilRecord(record);
            if (result.IsSuccess)
                return result;
        }

        return DiscoveryResult<string>.Fail(DiscoveryErrorKind.NotFound,
            "No valid Sigil TXT record found.");
    }

    private static Dictionary<string, string> ParseKeyValuePairs(string record)
    {
        var pairs = new Dictionary<string, string>(StringComparer.Ordinal);

        foreach (var token in record.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            var eqIdx = token.IndexOf('=', StringComparison.Ordinal);
            if (eqIdx > 0)
            {
                var key = token[..eqIdx];
                var value = token[(eqIdx + 1)..];
                pairs.TryAdd(key, value);
            }
        }

        return pairs;
    }
}
