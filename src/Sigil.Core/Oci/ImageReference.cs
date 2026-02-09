namespace Sigil.Oci;

/// <summary>
/// Parses and normalizes OCI image references.
/// Handles Docker Hub normalization, digest references, and port numbers.
/// </summary>
public sealed class ImageReference
{
    private const string DockerHubRegistry = "docker.io";
    private const string DockerHubApiEndpoint = "https://registry-1.docker.io";
    private const string DefaultTag = "latest";

    /// <summary>The registry hostname (e.g., "docker.io", "ghcr.io", "localhost:5000").</summary>
    public string Registry { get; }

    /// <summary>The repository path without registry (e.g., "library/alpine", "owner/repo").</summary>
    public string RepositoryPath { get; }

    /// <summary>The tag, if specified (e.g., "latest", "v1.0"). Null when using a digest reference.</summary>
    public string? Tag { get; }

    /// <summary>The digest, if specified (e.g., "sha256:abc123..."). Null when using a tag reference.</summary>
    public string? Digest { get; }

    /// <summary>The API base URL for this registry (e.g., "https://registry-1.docker.io").
    /// HTTP allowed for localhost; HTTPS enforced for all other registries.</summary>
    public string ApiEndpoint => Registry == DockerHubRegistry
        ? DockerHubApiEndpoint
        : IsLocalhost(Registry)
            ? $"http://{Registry}"
            : $"https://{Registry}";

    /// <summary>The canonical full name (e.g., "docker.io/library/alpine:latest").</summary>
    public string FullName => Digest is not null
        ? $"{Registry}/{RepositoryPath}@{Digest}"
        : $"{Registry}/{RepositoryPath}:{Tag}";

    /// <summary>The reference to use in manifest API calls (tag or digest).</summary>
    public string ManifestReference => Digest ?? Tag!;

    private ImageReference(string registry, string repositoryPath, string? tag, string? digest)
    {
        Registry = registry;
        RepositoryPath = repositoryPath;
        Tag = tag;
        Digest = digest;
    }

    /// <summary>
    /// Parses an image reference string into its components.
    /// Handles Docker Hub shorthand, default tags, and digest references.
    /// </summary>
    public static OciResult<ImageReference> Parse(string reference)
    {
        if (string.IsNullOrWhiteSpace(reference))
            return OciResult<ImageReference>.Fail(OciErrorKind.InvalidReference, "Image reference cannot be empty.");

        var input = reference.Trim();

        // Split off digest (@sha256:...)
        string? digest = null;
        var atIndex = input.IndexOf('@');
        if (atIndex >= 0)
        {
            digest = input[(atIndex + 1)..];
            input = input[..atIndex];
        }

        // Split off tag (:tag) — but not port numbers (host:port/repo)
        string? tag = null;
        if (digest is null)
        {
            var lastColon = input.LastIndexOf(':');
            if (lastColon >= 0)
            {
                var afterColon = input[(lastColon + 1)..];
                // If there's a slash after the colon, it's a port, not a tag
                if (!afterColon.Contains('/'))
                {
                    tag = afterColon;
                    input = input[..lastColon];
                }
            }
        }

        // Default tag when no tag and no digest
        if (tag is null && digest is null)
            tag = DefaultTag;

        // Split registry from repository path
        string registry;
        string repositoryPath;

        var firstSlash = input.IndexOf('/');
        if (firstSlash < 0)
        {
            // No slash: Docker Hub library image (e.g., "alpine")
            registry = DockerHubRegistry;
            repositoryPath = $"library/{input}";
        }
        else
        {
            var possibleRegistry = input[..firstSlash];
            // It's a registry if it contains a dot, a colon (port), or is "localhost"
            if (possibleRegistry.Contains('.') || possibleRegistry.Contains(':') ||
                string.Equals(possibleRegistry, "localhost", StringComparison.OrdinalIgnoreCase))
            {
                registry = possibleRegistry;
                repositoryPath = input[(firstSlash + 1)..];
            }
            else
            {
                // Docker Hub user repo (e.g., "myuser/myimage")
                registry = DockerHubRegistry;
                repositoryPath = input;
            }
        }

        if (string.IsNullOrEmpty(repositoryPath))
            return OciResult<ImageReference>.Fail(OciErrorKind.InvalidReference, $"Invalid image reference: '{reference}'.");

        return OciResult<ImageReference>.Ok(new ImageReference(registry, repositoryPath, tag, digest));
    }

    private static bool IsLocalhost(string registry)
    {
        var host = registry.Contains(':') ? registry[..registry.IndexOf(':')] : registry;
        return string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(host, "127.0.0.1", StringComparison.Ordinal) ||
               string.Equals(host, "::1", StringComparison.Ordinal);
    }
}
