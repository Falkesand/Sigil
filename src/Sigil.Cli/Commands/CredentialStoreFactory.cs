namespace Sigil.Cli.Commands;

public static class CredentialStoreFactory
{
    public static ICredentialStore? TryCreate()
    {
        if (!OperatingSystem.IsWindows())
            return null;

        return CreateWindowsStore();
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static WindowsCredentialStore CreateWindowsStore() => new();
}
