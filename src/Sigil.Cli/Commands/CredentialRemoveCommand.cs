using System.CommandLine;

namespace Sigil.Cli.Commands;

public static class CredentialRemoveCommand
{
    public static Command Create()
    {
        var keyOption = new Option<string>("--key") { Description = "Path to the private key file" };
        keyOption.Required = true;

        var cmd = new Command("remove", "Remove a stored passphrase from Windows Credential Manager");
        cmd.Add(keyOption);

        cmd.SetAction(parseResult =>
        {
            var keyPath = parseResult.GetValue(keyOption)!;

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

            var targetName = PassphraseResolver.BuildTargetName(keyPath);
            var result = store.Delete(targetName);
            if (!result.IsSuccess)
            {
                if (result.ErrorKind == CredentialStoreErrorKind.NotFound)
                    Console.Error.WriteLine($"No stored passphrase found for: {Path.GetFullPath(keyPath)}");
                else
                    Console.Error.WriteLine($"Failed to remove credential: {result.ErrorMessage}");
                Environment.ExitCode = 1;
                return;
            }

            Console.WriteLine($"Passphrase removed for: {Path.GetFullPath(keyPath)}");
        });

        return cmd;
    }
}
