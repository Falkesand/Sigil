using System.CommandLine;
using Sigil.Trust;

namespace Sigil.Cli.Commands;

public static class TrustIdentityRemoveCommand
{
    public static Command Create()
    {
        var bundleArg = new Argument<FileInfo>("bundle") { Description = "Path to the trust bundle" };
        var issuerOption = new Option<string>("--issuer") { Description = "OIDC issuer URL" };
        issuerOption.Required = true;
        var subjectOption = new Option<string>("--subject") { Description = "Subject pattern to remove" };
        subjectOption.Required = true;

        var cmd = new Command("identity-remove", "Remove a trusted OIDC identity from a bundle");
        cmd.Add(bundleArg);
        cmd.Add(issuerOption);
        cmd.Add(subjectOption);

        cmd.SetAction(parseResult =>
        {
            var bundleFile = parseResult.GetValue(bundleArg)!;
            var issuer = parseResult.GetValue(issuerOption)!;
            var subject = parseResult.GetValue(subjectOption)!;

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

            var removed = bundle.Identities.RemoveAll(i =>
                string.Equals(i.Issuer, issuer, StringComparison.Ordinal) &&
                string.Equals(i.SubjectPattern, subject, StringComparison.Ordinal));

            if (removed == 0)
            {
                Console.Error.WriteLine($"Identity not found: {subject} from {issuer}");
                return;
            }

            var serializeResult = BundleSigner.Serialize(bundle);
            if (!serializeResult.IsSuccess)
            {
                Console.Error.WriteLine($"Failed to serialize bundle: {serializeResult.ErrorMessage}");
                return;
            }

            File.WriteAllText(bundleFile.FullName, serializeResult.Value);
            Console.WriteLine($"Removed identity: {subject} from {issuer}");
        });

        return cmd;
    }
}
