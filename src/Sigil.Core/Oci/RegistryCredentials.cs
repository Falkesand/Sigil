namespace Sigil.Oci;

/// <summary>
/// Credentials for authenticating to an OCI registry.
/// </summary>
public sealed record RegistryCredentials
{
    public string? Username { get; init; }
    public string? Password { get; init; }
    public string? Token { get; init; }

    public bool IsAnonymous => Username is null && Token is null;

    public static RegistryCredentials Anonymous => new();

    public static RegistryCredentials FromBasicAuth(string base64)
    {
        var decoded = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(base64));
        var colonIndex = decoded.IndexOf(':');
        if (colonIndex < 0)
            return new RegistryCredentials { Username = decoded };

        return new RegistryCredentials
        {
            Username = decoded[..colonIndex],
            Password = decoded[(colonIndex + 1)..]
        };
    }

    public static RegistryCredentials FromBearerToken(string token) =>
        new() { Token = token };

    public string ToBasicHeaderValue()
    {
        var plain = $"{Username}:{Password}";
        return Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(plain));
    }
}
