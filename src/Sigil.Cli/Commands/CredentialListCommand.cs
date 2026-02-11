using System.CommandLine;

namespace Sigil.Cli.Commands;

public static class CredentialListCommand
{
    internal const string TargetPrefix = "sigil:passphrase:";

    public static Command Create()
    {
        var cmd = new Command("list", "List keys with stored passphrases in Windows Credential Manager");

        cmd.SetAction(_ =>
        {
            if (!OperatingSystem.IsWindows())
            {
                Console.Error.WriteLine("Credential storage is only supported on Windows.");
                Environment.ExitCode = 1;
                return;
            }

            var store = CredentialStoreFactory.TryCreate();
            if (store is null)
            {
                Console.Error.WriteLine("Credential storage is not available on this platform.");
                Environment.ExitCode = 1;
                return;
            }

            var result = store.List(TargetPrefix);
            if (!result.IsSuccess)
            {
                Console.Error.WriteLine($"Failed to list credentials: {result.ErrorMessage}");
                Environment.ExitCode = 1;
                return;
            }

            if (result.Value.Count == 0)
            {
                Console.WriteLine("No stored passphrases found.");
                return;
            }

            foreach (var target in result.Value)
            {
                // Strip prefix to show the key path
                var keyPath = target.StartsWith(TargetPrefix, StringComparison.Ordinal)
                    ? target[TargetPrefix.Length..]
                    : target;
                Console.WriteLine(keyPath);
            }
        });

        return cmd;
    }
}
