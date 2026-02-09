using System.Text.Json;

namespace Sigil.Oci;

/// <summary>
/// Parses ~/.docker/config.json to resolve registry credentials.
/// </summary>
public static class DockerConfigAuth
{
    private static readonly string[] DockerHubKeys =
    [
        "docker.io",
        "https://index.docker.io/v1/",
        "index.docker.io",
        "https://index.docker.io/v2/"
    ];

    /// <summary>
    /// Resolves credentials for a registry from the Docker config file.
    /// Returns null if no credentials found.
    /// </summary>
    public static RegistryCredentials? Resolve(string registry, string? configPath = null)
    {
        configPath ??= GetDefaultConfigPath();
        if (!File.Exists(configPath))
            return null;

        string json;
        try
        {
            json = File.ReadAllText(configPath);
        }
        catch (IOException)
        {
            return null;
        }

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(json);
        }
        catch (JsonException)
        {
            return null;
        }

        using (doc)
        {
            var root = doc.RootElement;

            // 1. credHelpers — per-registry credential helper
            if (root.TryGetProperty("credHelpers", out var credHelpers))
            {
                var helperName = FindHelperForRegistry(credHelpers, registry);
                if (helperName is not null)
                {
                    var result = CredentialHelperRunner.Get(helperName, registry);
                    if (result.IsSuccess)
                        return result.Value;
                }
            }

            // 2. credsStore — default credential helper
            if (root.TryGetProperty("credsStore", out var credsStore))
            {
                var storeName = credsStore.GetString();
                if (!string.IsNullOrEmpty(storeName))
                {
                    var result = CredentialHelperRunner.Get(storeName, registry);
                    if (result.IsSuccess)
                        return result.Value;
                }
            }

            // 3. auths — base64 encoded credentials
            if (root.TryGetProperty("auths", out var auths))
            {
                return FindAuthForRegistry(auths, registry);
            }

            return null;
        }
    }

    private static string? FindHelperForRegistry(JsonElement credHelpers, string registry)
    {
        if (credHelpers.TryGetProperty(registry, out var helper))
            return helper.GetString();

        // Docker Hub aliases
        if (IsDockerHub(registry))
        {
            foreach (var key in DockerHubKeys)
            {
                if (credHelpers.TryGetProperty(key, out helper))
                    return helper.GetString();
            }
        }

        return null;
    }

    private static RegistryCredentials? FindAuthForRegistry(JsonElement auths, string registry)
    {
        if (TryGetAuth(auths, registry, out var creds))
            return creds;

        // Docker Hub aliases
        if (IsDockerHub(registry))
        {
            foreach (var key in DockerHubKeys)
            {
                if (TryGetAuth(auths, key, out creds))
                    return creds;
            }
        }

        return null;
    }

    private static bool TryGetAuth(JsonElement auths, string key, out RegistryCredentials? creds)
    {
        creds = null;
        if (!auths.TryGetProperty(key, out var entry))
            return false;

        if (entry.TryGetProperty("auth", out var auth))
        {
            var base64 = auth.GetString();
            if (!string.IsNullOrEmpty(base64))
            {
                creds = RegistryCredentials.FromBasicAuth(base64);
                return true;
            }
        }

        return false;
    }

    private static bool IsDockerHub(string registry) =>
        string.Equals(registry, "docker.io", StringComparison.OrdinalIgnoreCase) ||
        registry.Contains("index.docker.io", StringComparison.OrdinalIgnoreCase);

    private static string GetDefaultConfigPath()
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return Path.Combine(home, ".docker", "config.json");
    }
}
