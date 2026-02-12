using System.CommandLine;

namespace Sigil.Cli.Commands;

public static class GraphCommand
{
    public static Command Create()
    {
        var cmd = new Command("graph", "Build and query trust graphs");
        cmd.Add(GraphBuildCommand.Create());
        cmd.Add(GraphQueryCommand.Create());
        cmd.Add(GraphExportCommand.Create());
        return cmd;
    }
}
