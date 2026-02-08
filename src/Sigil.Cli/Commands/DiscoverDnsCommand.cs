using System.CommandLine;
using Sigil.Discovery;

namespace Sigil.Cli.Commands;

public static class DiscoverDnsCommand
{
    public static Command Create()
    {
        var domainArg = new Argument<string>("domain") { Description = "Domain name to look up DNS TXT records for" };
        var outputOption = new Option<string?>("-o") { Description = "Save the trust bundle to a file" };

        var cmd = new Command("dns", "Look up DNS TXT records for a trust bundle");
        cmd.Add(domainArg);
        cmd.Add(outputOption);

        cmd.SetAction(async parseResult =>
        {
            var domain = parseResult.GetValue(domainArg)!;
            var output = parseResult.GetValue(outputOption);

            var resolver = new DnsDiscovery();
            var result = await resolver.ResolveAsync(domain);

            if (!result.IsSuccess)
            {
                Console.Error.WriteLine($"DNS discovery failed: {result.ErrorMessage}");
                return;
            }

            DiscoverWellKnownCommand.PrintBundleSummary(result.Value);

            if (output is not null)
            {
                File.WriteAllText(output, result.Value);
                Console.WriteLine($"Saved to: {output}");
            }
        });

        return cmd;
    }
}
