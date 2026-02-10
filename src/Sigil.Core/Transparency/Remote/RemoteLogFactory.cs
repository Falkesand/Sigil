namespace Sigil.Transparency.Remote;

public static class RemoteLogFactory
{
    public static IRemoteLog Create(string logUrl, string? apiKey = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(logUrl);

        // "rekor" shorthand → Sigstore public Rekor
        if (string.Equals(logUrl, "rekor", StringComparison.OrdinalIgnoreCase))
            return new RekorClient();

        // "rekor:https://..." → custom Rekor instance
        if (logUrl.StartsWith("rekor:", StringComparison.OrdinalIgnoreCase))
        {
            var customUrl = logUrl[6..]; // strip "rekor:" prefix
            return new RekorClient(customUrl);
        }

        // Anything else → Sigil log server (requires API key)
        if (string.IsNullOrWhiteSpace(apiKey))
            throw new ArgumentException(
                "API key is required for Sigil log server URLs. Use --log-api-key.", nameof(apiKey));

        return new SigilLogClient(logUrl, apiKey);
    }
}
