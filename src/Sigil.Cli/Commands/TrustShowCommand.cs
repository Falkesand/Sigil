using System.CommandLine;
using Sigil.Trust;

namespace Sigil.Cli.Commands;

public static class TrustShowCommand
{
    public static Command Create()
    {
        var bundleArg = new Argument<FileInfo>("bundle") { Description = "Path to the trust bundle" };

        var cmd = new Command("show", "Display the contents of a trust bundle");
        cmd.Add(bundleArg);

        cmd.SetAction(parseResult =>
        {
            var bundleFile = parseResult.GetValue(bundleArg)!;

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

            Console.WriteLine($"Trust Bundle: {bundle.Metadata.Name}");
            Console.WriteLine($"Version: {bundle.Version}");
            if (bundle.Metadata.Description is not null)
                Console.WriteLine($"Description: {bundle.Metadata.Description}");
            Console.WriteLine($"Created: {bundle.Metadata.Created}");
            Console.WriteLine();

            Console.WriteLine($"Keys ({bundle.Keys.Count}):");
            foreach (var key in bundle.Keys)
            {
                var name = key.DisplayName is not null ? $" ({key.DisplayName})" : "";
                Console.WriteLine($"  {key.Fingerprint}{name}");
                if (key.NotAfter is not null)
                    Console.WriteLine($"    Expires: {key.NotAfter}");
                if (key.Scopes is not null)
                {
                    if (key.Scopes.NamePatterns is { Count: > 0 })
                        Console.WriteLine($"    Names: {string.Join(", ", key.Scopes.NamePatterns)}");
                    if (key.Scopes.Labels is { Count: > 0 })
                        Console.WriteLine($"    Labels: {string.Join(", ", key.Scopes.Labels)}");
                    if (key.Scopes.Algorithms is { Count: > 0 })
                        Console.WriteLine($"    Algorithms: {string.Join(", ", key.Scopes.Algorithms)}");
                }
            }

            if (bundle.Endorsements.Count > 0)
            {
                Console.WriteLine();
                Console.WriteLine($"Endorsements ({bundle.Endorsements.Count}):");
                foreach (var e in bundle.Endorsements)
                {
                    Console.WriteLine($"  {e.Endorser} -> {e.Endorsed}");
                    if (e.Statement is not null)
                        Console.WriteLine($"    Statement: {e.Statement}");
                    if (e.NotAfter is not null)
                        Console.WriteLine($"    Expires: {e.NotAfter}");
                }
            }

            if (bundle.Identities.Count > 0)
            {
                Console.WriteLine();
                Console.WriteLine($"Identities ({bundle.Identities.Count}):");
                foreach (var identity in bundle.Identities)
                {
                    var name = identity.DisplayName is not null ? $" ({identity.DisplayName})" : "";
                    Console.WriteLine($"  {identity.Issuer} -> {identity.SubjectPattern}{name}");
                    if (identity.NotAfter is not null)
                        Console.WriteLine($"    Expires: {identity.NotAfter}");
                }
            }

            if (bundle.Revocations.Count > 0)
            {
                Console.WriteLine();
                Console.WriteLine($"Revocations ({bundle.Revocations.Count}):");
                foreach (var rev in bundle.Revocations)
                {
                    Console.WriteLine($"  {rev.Fingerprint}");
                    Console.WriteLine($"    Revoked at: {rev.RevokedAt}");
                    if (rev.Reason is not null)
                        Console.WriteLine($"    Reason: {rev.Reason}");
                }
            }

            Console.WriteLine();
            if (bundle.Signature is not null)
            {
                Console.WriteLine("Signature: PRESENT");
                Console.WriteLine($"  Signed by: {bundle.Signature.KeyId}");
                Console.WriteLine($"  Algorithm: {bundle.Signature.Algorithm}");
                Console.WriteLine($"  Timestamp: {bundle.Signature.Timestamp}");
            }
            else
            {
                Console.WriteLine("Signature: UNSIGNED");
            }
        });

        return cmd;
    }
}
