using System.CommandLine;

namespace Sigil.Cli.Commands;

public static class DiscoverCommand
{
    public static Command Create()
    {
        var cmd = new Command("discover", "Discover trust bundles from well-known URLs, DNS, or git repositories");
        cmd.Add(DiscoverWellKnownCommand.Create());
        cmd.Add(DiscoverDnsCommand.Create());
        cmd.Add(DiscoverGitCommand.Create());
        return cmd;
    }
}
