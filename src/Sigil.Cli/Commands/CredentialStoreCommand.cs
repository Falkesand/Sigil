using System.CommandLine;

namespace Sigil.Cli.Commands;

public static class CredentialStoreCommand
{
    public static Command Create()
    {
        var keyOption = new Option<string>("--key") { Description = "Path to the private key file" };
        keyOption.Required = true;

        var cmd = new Command("store", "Store a passphrase for a key in Windows Credential Manager");
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

            if (!File.Exists(keyPath))
            {
                Console.Error.WriteLine($"Key file not found: {keyPath}");
                Environment.ExitCode = 1;
                return;
            }

            // Prompt for passphrase
            var prompter = ConsolePrompter.Instance;
            if (!prompter.IsInteractive)
            {
                Console.Error.WriteLine("Interactive terminal required to enter passphrase.");
                Environment.ExitCode = 1;
                return;
            }

            var passphrase = prompter.ReadPassphrase("Enter passphrase for key: ");
            if (string.IsNullOrEmpty(passphrase))
            {
                Console.Error.WriteLine("No passphrase entered.");
                Environment.ExitCode = 1;
                return;
            }

            // Validate passphrase by attempting to load the key
            var loadResult = KeyLoader.Load(keyPath, passphrase, null);
            if (!loadResult.IsSuccess)
            {
                Console.Error.WriteLine($"Failed to decrypt key: {loadResult.ErrorMessage}");
                Environment.ExitCode = 1;
                return;
            }

            loadResult.Value.Dispose();

            // Store in credential manager
            var store = CredentialStoreFactory.TryCreate();
            if (store is null)
            {
                Console.Error.WriteLine("Credential storage is not available on this platform.");
                Environment.ExitCode = 1;
                return;
            }

            var targetName = PassphraseResolver.BuildTargetName(keyPath);
            var storeResult = store.Store(targetName, passphrase);
            if (!storeResult.IsSuccess)
            {
                Console.Error.WriteLine($"Failed to store credential: {storeResult.ErrorMessage}");
                Environment.ExitCode = 1;
                return;
            }

            Console.WriteLine($"Passphrase stored for: {Path.GetFullPath(keyPath)}");
        });

        return cmd;
    }
}
