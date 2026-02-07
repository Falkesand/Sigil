using System.CommandLine;
using Sigil.Trust;

namespace Sigil.Cli.Commands;

public static class TrustRemoveCommand
{
    public static Command Create()
    {
        var bundleArg = new Argument<FileInfo>("bundle") { Description = "Path to the trust bundle" };
        var fingerprintOption = new Option<string>("--fingerprint") { Description = "Key fingerprint to remove" };
        fingerprintOption.Required = true;

        var cmd = new Command("remove", "Remove a trusted key from a bundle");
        cmd.Add(bundleArg);
        cmd.Add(fingerprintOption);

        cmd.SetAction(parseResult =>
        {
            var bundleFile = parseResult.GetValue(bundleArg)!;
            var fingerprint = parseResult.GetValue(fingerprintOption)!;

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

            var removed = bundle.Keys.RemoveAll(k =>
                string.Equals(k.Fingerprint, fingerprint, StringComparison.Ordinal));

            if (removed == 0)
            {
                Console.Error.WriteLine($"Key {fingerprint} not found in bundle.");
                return;
            }

            var serializeResult = BundleSigner.Serialize(bundle);
            if (!serializeResult.IsSuccess)
            {
                Console.Error.WriteLine($"Failed to serialize bundle: {serializeResult.ErrorMessage}");
                return;
            }

            File.WriteAllText(bundleFile.FullName, serializeResult.Value);
            Console.WriteLine($"Removed key {fingerprint} from bundle.");
        });

        return cmd;
    }
}
