using System.CommandLine;

namespace Sigil.Cli.Commands;

public static class LogCommand
{
    public static Command Create()
    {
        var cmd = new Command("log", "Manage transparency log");
        cmd.Add(LogAppendCommand.Create());
        cmd.Add(LogVerifyCommand.Create());
        cmd.Add(LogSearchCommand.Create());
        cmd.Add(LogShowCommand.Create());
        cmd.Add(LogProofCommand.Create());
        return cmd;
    }
}
