using System.CommandLine;
using Sigil.Trust;

namespace Sigil.Cli.Commands;

public static class TrustAddCommand
{
    public static Command Create()
    {
        var bundleArg = new Argument<FileInfo>("bundle") { Description = "Path to the trust bundle" };
        var fingerprintOption = new Option<string>("--fingerprint") { Description = "Key fingerprint (sha256:hex)" };
        fingerprintOption.Required = true;
        var nameOption = new Option<string?>("--name") { Description = "Display name for the key" };
        var notAfterOption = new Option<string?>("--not-after") { Description = "Expiry date (ISO 8601)" };
        var scopeNamesOption = new Option<string[]?>("--scope-names") { Description = "Allowed name patterns (glob)" };
        var scopeLabelsOption = new Option<string[]?>("--scope-labels") { Description = "Allowed labels" };
        var scopeAlgorithmsOption = new Option<string[]?>("--scope-algorithms") { Description = "Allowed algorithms" };

        var cmd = new Command("add", "Add a trusted key to a bundle");
        cmd.Add(bundleArg);
        cmd.Add(fingerprintOption);
        cmd.Add(nameOption);
        cmd.Add(notAfterOption);
        cmd.Add(scopeNamesOption);
        cmd.Add(scopeLabelsOption);
        cmd.Add(scopeAlgorithmsOption);

        cmd.SetAction(parseResult =>
        {
            var bundleFile = parseResult.GetValue(bundleArg)!;
            var fingerprint = parseResult.GetValue(fingerprintOption)!;
            var displayName = parseResult.GetValue(nameOption);
            var notAfter = parseResult.GetValue(notAfterOption);
            var scopeNames = parseResult.GetValue(scopeNamesOption);
            var scopeLabels = parseResult.GetValue(scopeLabelsOption);
            var scopeAlgorithms = parseResult.GetValue(scopeAlgorithmsOption);

            if (!bundleFile.Exists)
            {
                Console.Error.WriteLine($"Bundle not found: {bundleFile.FullName}");
                return;
            }

            var json = File.ReadAllText(bundleFile.FullName);
            var deserializeResult = BundleSigner.Deserialize(json);
            if (!deserializeResult.IsSuccess)
            {
                Console.Error.WriteLine($"Failed to parse bundle: {deserializeResult.ErrorMessage}");
                return;
            }

            var bundle = deserializeResult.Value;

            if (bundle.Signature is not null)
            {
                Console.Error.WriteLine("Cannot modify a signed bundle. Remove the signature first or create a new bundle.");
                return;
            }

            TrustScopes? scopes = null;
            if (scopeNames is { Length: > 0 } || scopeLabels is { Length: > 0 } || scopeAlgorithms is { Length: > 0 })
            {
                scopes = new TrustScopes
                {
                    NamePatterns = scopeNames is { Length: > 0 } ? [.. scopeNames] : null,
                    Labels = scopeLabels is { Length: > 0 } ? [.. scopeLabels] : null,
                    Algorithms = scopeAlgorithms is { Length: > 0 } ? [.. scopeAlgorithms] : null
                };
            }

            bundle.Keys.Add(new TrustedKeyEntry
            {
                Fingerprint = fingerprint,
                DisplayName = displayName,
                NotAfter = notAfter,
                Scopes = scopes
            });

            var serializeResult = BundleSigner.Serialize(bundle);
            if (!serializeResult.IsSuccess)
            {
                Console.Error.WriteLine($"Failed to serialize bundle: {serializeResult.ErrorMessage}");
                return;
            }

            File.WriteAllText(bundleFile.FullName, serializeResult.Value);
            Console.WriteLine($"Added key {fingerprint} to bundle.");
        });

        return cmd;
    }
}
