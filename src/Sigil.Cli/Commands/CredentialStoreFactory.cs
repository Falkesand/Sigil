namespace Sigil.Cli.Commands;

/// <summary>
/// Creates the platform-appropriate <see cref="ICredentialStore"/> implementation.
/// Returns <c>null</c> on platforms without credential store support.
/// </summary>
public static class CredentialStoreFactory
{
    /// <summary>
    /// Returns a <see cref="WindowsCredentialStore"/> on Windows, or <c>null</c> on other platforms.
    /// </summary>
    public static ICredentialStore? TryCreate()
    {
        if (!OperatingSystem.IsWindows())
            return null;

        return CreateWindowsStore();
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static WindowsCredentialStore CreateWindowsStore() => new();
}
