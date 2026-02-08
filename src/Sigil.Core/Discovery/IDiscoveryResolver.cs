namespace Sigil.Discovery;

public interface IDiscoveryResolver
{
    Task<DiscoveryResult<string>> ResolveAsync(string identifier, CancellationToken cancellationToken = default);
}
