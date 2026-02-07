using System.CommandLine;
using System.Globalization;
using Sigil.Trust;

namespace Sigil.Cli.Commands;

public static class TrustEndorseCommand
{
    public static Command Create()
    {
        var bundleArg = new Argument<FileInfo>("bundle") { Description = "Path to the trust bundle" };
        var endorserOption = new Option<string>("--endorser") { Description = "Endorser key fingerprint" };
        endorserOption.Required = true;
        var endorsedOption = new Option<string>("--endorsed") { Description = "Endorsed key fingerprint" };
        endorsedOption.Required = true;
        var statementOption = new Option<string?>("--statement") { Description = "Endorsement statement" };
        var notAfterOption = new Option<string?>("--not-after") { Description = "Endorsement expiry (ISO 8601)" };
        var scopeNamesOption = new Option<string[]?>("--scope-names") { Description = "Allowed name patterns (glob)" };
        var scopeLabelsOption = new Option<string[]?>("--scope-labels") { Description = "Allowed labels" };

        var cmd = new Command("endorse", "Add an endorsement to a bundle");
        cmd.Add(bundleArg);
        cmd.Add(endorserOption);
        cmd.Add(endorsedOption);
        cmd.Add(statementOption);
        cmd.Add(notAfterOption);
        cmd.Add(scopeNamesOption);
        cmd.Add(scopeLabelsOption);

        cmd.SetAction(parseResult =>
        {
            var bundleFile = parseResult.GetValue(bundleArg)!;
            var endorser = parseResult.GetValue(endorserOption)!;
            var endorsed = parseResult.GetValue(endorsedOption)!;
            var statement = parseResult.GetValue(statementOption);
            var notAfter = parseResult.GetValue(notAfterOption);
            var scopeNames = parseResult.GetValue(scopeNamesOption);
            var scopeLabels = parseResult.GetValue(scopeLabelsOption);

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
            if (scopeNames is { Length: > 0 } || scopeLabels is { Length: > 0 })
            {
                scopes = new TrustScopes
                {
                    NamePatterns = scopeNames is { Length: > 0 } ? [.. scopeNames] : null,
                    Labels = scopeLabels is { Length: > 0 } ? [.. scopeLabels] : null
                };
            }

            bundle.Endorsements.Add(new Endorsement
            {
                Endorser = endorser,
                Endorsed = endorsed,
                Statement = statement,
                Scopes = scopes,
                NotAfter = notAfter,
                Timestamp = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ",
                    CultureInfo.InvariantCulture)
            });

            var serializeResult = BundleSigner.Serialize(bundle);
            if (!serializeResult.IsSuccess)
            {
                Console.Error.WriteLine($"Failed to serialize bundle: {serializeResult.ErrorMessage}");
                return;
            }

            File.WriteAllText(bundleFile.FullName, serializeResult.Value);
            Console.WriteLine($"Added endorsement: {endorser} -> {endorsed}");
        });

        return cmd;
    }
}
