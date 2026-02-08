using System.CommandLine;
using Sigil.Discovery;
using Sigil.Trust;

namespace Sigil.Cli.Commands;

public static class DiscoverWellKnownCommand
{
    public static Command Create()
    {
        var domainArg = new Argument<string>("domain") { Description = "Domain name or HTTPS URL to fetch trust bundle from" };
        var outputOption = new Option<string?>("-o") { Description = "Save the trust bundle to a file" };

        var cmd = new Command("well-known", "Fetch trust bundle from a well-known URL");
        cmd.Add(domainArg);
        cmd.Add(outputOption);

        cmd.SetAction(async parseResult =>
        {
            var domain = parseResult.GetValue(domainArg)!;
            var output = parseResult.GetValue(outputOption);

            var resolver = new WellKnownResolver();
            var result = await resolver.ResolveAsync(domain);

            if (!result.IsSuccess)
            {
                Console.Error.WriteLine($"Discovery failed: {result.ErrorMessage}");
                return;
            }

            PrintBundleSummary(result.Value);

            if (output is not null)
            {
                File.WriteAllText(output, result.Value);
                Console.WriteLine($"Saved to: {output}");
            }
        });

        return cmd;
    }

    internal static void PrintBundleSummary(string json)
    {
        var deserializeResult = BundleSigner.Deserialize(json);
        if (!deserializeResult.IsSuccess)
        {
            Console.WriteLine("Bundle: (could not parse)");
            return;
        }

        var bundle = deserializeResult.Value;
        Console.WriteLine($"Bundle: {bundle.Metadata.Name}");
        Console.WriteLine($"Keys: {bundle.Keys.Count}");
        Console.WriteLine($"Signature: {(bundle.Signature is not null ? "SIGNED" : "UNSIGNED")}");
    }
}
