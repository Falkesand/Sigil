using System.CommandLine;
using Sigil.Discovery;

namespace Sigil.Cli.Commands;

public static class DiscoverGitCommand
{
    public static Command Create()
    {
        var urlArg = new Argument<string>("url") { Description = "Git repository URL (use #branch for specific branch/tag)" };
        var outputOption = new Option<string?>("-o") { Description = "Save the trust bundle to a file" };

        var cmd = new Command("git", "Fetch trust bundle from a git repository");
        cmd.Add(urlArg);
        cmd.Add(outputOption);

        cmd.SetAction(async parseResult =>
        {
            var url = parseResult.GetValue(urlArg)!;
            var output = parseResult.GetValue(outputOption);

            var resolver = new GitBundleResolver();
            var result = await resolver.ResolveAsync(url);

            if (!result.IsSuccess)
            {
                Console.Error.WriteLine($"Git discovery failed: {result.ErrorMessage}");
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
