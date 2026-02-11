using System.CommandLine;

namespace Sigil.Cli.Commands;

public static class CredentialCommand
{
    public static Command Create()
    {
        var cmd = new Command("credential", "Manage stored passphrases in Windows Credential Manager");
        cmd.Add(CredentialStoreCommand.Create());
        cmd.Add(CredentialRemoveCommand.Create());
        cmd.Add(CredentialListCommand.Create());
        return cmd;
    }
}
