namespace Sigil.Cli.Commands;

public interface IConsolePrompter
{
    bool IsInteractive { get; }
    string? ReadPassphrase(string prompt);
}
