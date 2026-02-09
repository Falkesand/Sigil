using System.CommandLine;

namespace Sigil.Cli.Commands;

public static class GitCommand
{
    public static Command Create()
    {
        var cmd = new Command("git", "Git integration for Sigil signing");
        cmd.Add(GitConfigCommand.Create());
        return cmd;
    }
}
