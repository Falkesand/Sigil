using System.CommandLine;
using Sigil.Trust;

namespace Sigil.Cli.Commands;

public static class TrustIdentityAddCommand
{
    public static Command Create()
    {
        var bundleArg = new Argument<FileInfo>("bundle") { Description = "Path to the trust bundle" };
        var issuerOption = new Option<string>("--issuer") { Description = "OIDC issuer URL" };
        issuerOption.Required = true;
        var subjectOption = new Option<string>("--subject") { Description = "Subject pattern (glob)" };
        subjectOption.Required = true;
        var nameOption = new Option<string?>("--name") { Description = "Display name for this identity" };
        var notAfterOption = new Option<string?>("--not-after") { Description = "Expiry date (ISO 8601)" };

        var cmd = new Command("identity-add", "Add a trusted OIDC identity to a bundle");
        cmd.Add(bundleArg);
        cmd.Add(issuerOption);
        cmd.Add(subjectOption);
        cmd.Add(nameOption);
        cmd.Add(notAfterOption);

        cmd.SetAction(parseResult =>
        {
            var bundleFile = parseResult.GetValue(bundleArg)!;
            var issuer = parseResult.GetValue(issuerOption)!;
            var subject = parseResult.GetValue(subjectOption)!;
            var displayName = parseResult.GetValue(nameOption);
            var notAfter = parseResult.GetValue(notAfterOption);

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

            bundle.Identities.Add(new TrustedIdentity
            {
                Issuer = issuer,
                SubjectPattern = subject,
                DisplayName = displayName,
                NotAfter = notAfter
            });

            var serializeResult = BundleSigner.Serialize(bundle);
            if (!serializeResult.IsSuccess)
            {
                Console.Error.WriteLine($"Failed to serialize bundle: {serializeResult.ErrorMessage}");
                return;
            }

            File.WriteAllText(bundleFile.FullName, serializeResult.Value);
            Console.WriteLine($"Added identity: {subject} from {issuer}");
        });

        return cmd;
    }
}
