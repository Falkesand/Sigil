using System.CommandLine;
using System.Globalization;
using Sigil.Trust;

namespace Sigil.Cli.Commands;

public static class TrustRevokeCommand
{
    public static Command Create()
    {
        var bundleArg = new Argument<FileInfo>("bundle") { Description = "Path to the trust bundle" };
        var fingerprintOption = new Option<string>("--fingerprint") { Description = "Key fingerprint to revoke" };
        fingerprintOption.Required = true;
        var reasonOption = new Option<string?>("--reason") { Description = "Reason for revocation" };

        var cmd = new Command("revoke", "Revoke a key in a trust bundle");
        cmd.Add(bundleArg);
        cmd.Add(fingerprintOption);
        cmd.Add(reasonOption);

        cmd.SetAction(parseResult =>
        {
            var bundleFile = parseResult.GetValue(bundleArg)!;
            var fingerprint = parseResult.GetValue(fingerprintOption)!;
            var reason = parseResult.GetValue(reasonOption);

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

            bundle.Revocations.Add(new RevocationEntry
            {
                Fingerprint = fingerprint,
                RevokedAt = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ",
                    CultureInfo.InvariantCulture),
                Reason = reason
            });

            var serializeResult = BundleSigner.Serialize(bundle);
            if (!serializeResult.IsSuccess)
            {
                Console.Error.WriteLine($"Failed to serialize bundle: {serializeResult.ErrorMessage}");
                return;
            }

            File.WriteAllText(bundleFile.FullName, serializeResult.Value);
            Console.WriteLine($"Revoked key {fingerprint} in bundle.");
        });

        return cmd;
    }
}
