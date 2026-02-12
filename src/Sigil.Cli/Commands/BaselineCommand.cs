using System.CommandLine;

namespace Sigil.Cli.Commands;

public static class BaselineCommand
{
    public static Command Create()
    {
        var cmd = new Command("baseline", "Manage anomaly detection baselines");
        cmd.Add(BaselineLearnCommand.Create());
        return cmd;
    }
}
