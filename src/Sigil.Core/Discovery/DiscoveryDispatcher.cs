namespace Sigil.Discovery;

/// <summary>
/// Dispatches discovery requests to the appropriate resolver based on URI scheme.
/// Supported schemes: https://, http://localhost, dns:, git:, bare domain.
/// </summary>
public sealed class DiscoveryDispatcher : IDiscoveryResolver
{
    private readonly WellKnownResolver _wellKnownResolver;
    private readonly DnsDiscovery _dnsDiscovery;
    private readonly GitBundleResolver _gitResolver;

    public DiscoveryDispatcher(HttpClient httpClient)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        _wellKnownResolver = new WellKnownResolver(httpClient);
        _dnsDiscovery = new DnsDiscovery(_wellKnownResolver);
        _gitResolver = new GitBundleResolver();
    }

    public DiscoveryDispatcher() : this(new HttpClient { Timeout = TimeSpan.FromSeconds(30) })
    {
    }

    public Task<DiscoveryResult<string>> ResolveAsync(
        string identifier,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(identifier);

        var scheme = DetectScheme(identifier);

        return scheme switch
        {
            "WellKnown" => _wellKnownResolver.ResolveAsync(identifier, cancellationToken),
            "Dns" => _dnsDiscovery.ResolveAsync(identifier[4..], cancellationToken), // strip "dns:"
            "Git" => _gitResolver.ResolveAsync(identifier[4..], cancellationToken),  // strip "git:"
            _ => Task.FromResult(DiscoveryResult<string>.Fail(
                DiscoveryErrorKind.InvalidUri, $"Cannot determine resolver for: {identifier}"))
        };
    }

    /// <summary>
    /// Detects the discovery scheme from a URI string.
    /// </summary>
    public static string DetectScheme(string identifier)
    {
        if (identifier.StartsWith("dns:", StringComparison.OrdinalIgnoreCase))
            return "Dns";

        if (identifier.StartsWith("git:", StringComparison.OrdinalIgnoreCase))
            return "Git";

        if (identifier.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ||
            identifier.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
            return "WellKnown";

        // Bare domain — treat as well-known
        return "WellKnown";
    }
}
