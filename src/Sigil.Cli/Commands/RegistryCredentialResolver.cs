using Sigil.Oci;

namespace Sigil.Cli.Commands;

/// <summary>
/// Resolves credentials for an OCI registry using environment variables,
/// Docker config, and anonymous fallback.
/// </summary>
internal static class RegistryCredentialResolver
{
    public static RegistryCredentials Resolve(string registry)
    {
        // 1. Environment variables
        var envUser = Environment.GetEnvironmentVariable("SIGIL_REGISTRY_USERNAME");
        var envPass = Environment.GetEnvironmentVariable("SIGIL_REGISTRY_PASSWORD");
        if (!string.IsNullOrEmpty(envUser))
            return new RegistryCredentials { Username = envUser, Password = envPass };

        // 2. Docker config
        var dockerCreds = DockerConfigAuth.Resolve(registry);
        if (dockerCreds is not null)
            return dockerCreds;

        // 3. Anonymous
        return RegistryCredentials.Anonymous;
    }
}
