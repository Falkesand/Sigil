using System.CommandLine;
using Secure.Sbom.Crypto;
using Secure.Sbom.Keys;

namespace Secure.Sbom.Cli.Commands;

public static class KeysCommand
{
    public static Command Create()
    {
        var cmd = new Command("keys", "Manage signing keys");

        cmd.Add(CreateGenerateCommand());
        cmd.Add(CreateListCommand());
        cmd.Add(CreateExportCommand());
        cmd.Add(CreateImportCommand());

        return cmd;
    }

    private static Command CreateGenerateCommand()
    {
        var labelOption = new Option<string?>("--label") { Description = "Human-readable label for the key" };
        var passphraseOption = new Option<string?>("--passphrase") { Description = "Passphrase to encrypt the private key" };

        var cmd = new Command("generate", "Generate a new signing key pair");
        cmd.Add(labelOption);
        cmd.Add(passphraseOption);

        cmd.SetAction(parseResult =>
        {
            var label = parseResult.GetValue(labelOption);
            var passphrase = parseResult.GetValue(passphraseOption);

            var store = KeyStore.Default();
            var fingerprint = store.GenerateKey(SigningAlgorithm.ECDsaP256, label, passphrase);

            Console.WriteLine($"Key generated: {fingerprint.Value}");
            if (label is not null)
                Console.WriteLine($"Label: {label}");
            if (passphrase is not null)
                Console.WriteLine("Private key encrypted with passphrase.");
        });

        return cmd;
    }

    private static Command CreateListCommand()
    {
        var cmd = new Command("list", "List all keys in the key store");

        cmd.SetAction(_ =>
        {
            var store = KeyStore.Default();
            var keys = store.ListKeys();

            if (keys.Count == 0)
            {
                Console.WriteLine("No keys found. Run 'sbom-sign keys generate' to create one.");
                return;
            }

            foreach (var key in keys)
            {
                var privateIndicator = key.HasPrivateKey ? " [private]" : " [public]";
                var label = key.Label is not null ? $" ({key.Label})" : "";
                Console.WriteLine($"  {key.Fingerprint}{label}{privateIndicator}");
                Console.WriteLine($"    Algorithm: {key.Algorithm}  Created: {key.CreatedAt:yyyy-MM-dd}");
            }
        });

        return cmd;
    }

    private static Command CreateExportCommand()
    {
        var fingerprintArg = new Argument<string>("fingerprint") { Description = "Key fingerprint to export" };

        var cmd = new Command("export", "Export a public key as PEM");
        cmd.Add(fingerprintArg);

        cmd.SetAction(parseResult =>
        {
            var fpString = parseResult.GetValue(fingerprintArg)!;
            var store = KeyStore.Default();
            var fingerprint = ResolveFingerprint(store, fpString);

            var pem = store.ExportPublicKeyPem(fingerprint);
            Console.WriteLine(pem);
        });

        return cmd;
    }

    private static Command CreateImportCommand()
    {
        var fileArg = new Argument<FileInfo>("file") { Description = "Path to a PEM file to import" };
        var labelOption = new Option<string?>("--label") { Description = "Label for the imported key" };

        var cmd = new Command("import", "Import a public key from a PEM file");
        cmd.Add(fileArg);
        cmd.Add(labelOption);

        cmd.SetAction(parseResult =>
        {
            var file = parseResult.GetValue(fileArg)!;
            var label = parseResult.GetValue(labelOption);

            if (!file.Exists)
            {
                Console.Error.WriteLine($"File not found: {file.FullName}");
                return;
            }

            var pem = File.ReadAllText(file.FullName);
            var store = KeyStore.Default();
            var fingerprint = store.ImportPublicKey(pem, label);

            Console.WriteLine($"Key imported: {fingerprint.Value}");
        });

        return cmd;
    }

    /// <summary>
    /// Resolves a fingerprint string to a KeyFingerprint, supporting prefix matching.
    /// </summary>
    internal static KeyFingerprint ResolveFingerprint(KeyStore store, string input)
    {
        // If it's a full fingerprint, use directly
        if (input.StartsWith("sha256:", StringComparison.Ordinal) && input.Length == 71)
            return KeyFingerprint.Parse(input);

        // Try prefix matching
        var keys = store.ListKeys();
        var matches = keys
            .Where(k => k.Fingerprint.Contains(input, StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (matches.Count == 0)
            throw new InvalidOperationException($"No key found matching '{input}'.");
        if (matches.Count > 1)
            throw new InvalidOperationException($"Ambiguous key reference '{input}' — matches {matches.Count} keys.");

        return KeyFingerprint.Parse(matches[0].Fingerprint);
    }
}
