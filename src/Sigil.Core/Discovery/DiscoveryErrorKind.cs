namespace Sigil.Discovery;

public enum DiscoveryErrorKind
{
    NetworkError,
    Timeout,
    NotFound,
    InvalidBundle,
    DnsError,
    GitError,
    InvalidUri
}
