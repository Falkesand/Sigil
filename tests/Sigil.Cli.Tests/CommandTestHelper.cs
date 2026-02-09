using System.CommandLine;
using Sigil.Cli.Commands;

namespace Sigil.Cli.Tests;

/// <summary>
/// Helper for invoking CLI commands programmatically and capturing output.
/// Uses a lock to prevent Console.SetOut/SetError stomping across parallel tests.
/// </summary>
public static class CommandTestHelper
{
    private static readonly SemaphoreSlim ConsoleLock = new(1, 1);

    public static async Task<CommandResult> InvokeAsync(params string[] args)
    {
        await ConsoleLock.WaitAsync();

        var stdOut = new StringWriter();
        var stdErr = new StringWriter();

        var originalOut = Console.Out;
        var originalErr = Console.Error;

        try
        {
            Console.SetOut(stdOut);
            Console.SetError(stdErr);

            var rootCommand = new RootCommand("sigil test");
            rootCommand.Add(GenerateCommand.Create());
            rootCommand.Add(SignCommand.Create());
            rootCommand.Add(VerifyCommand.Create());

            var trustCommand = new Command("trust", "Manage trust bundles");
            trustCommand.Add(TrustCreateCommand.Create());
            trustCommand.Add(TrustAddCommand.Create());
            trustCommand.Add(TrustRemoveCommand.Create());
            trustCommand.Add(TrustEndorseCommand.Create());
            trustCommand.Add(TrustSignCommand.Create());
            trustCommand.Add(TrustShowCommand.Create());
            trustCommand.Add(TrustRevokeCommand.Create());
            rootCommand.Add(trustCommand);
            rootCommand.Add(DiscoverCommand.Create());
            rootCommand.Add(TimestampCommand.Create());
            rootCommand.Add(AttestCommand.Create());
            rootCommand.Add(VerifyAttestationCommand.Create());
            rootCommand.Add(LogCommand.Create());
            rootCommand.Add(GitCommand.Create());
            rootCommand.Add(SignImageCommand.Create());
            rootCommand.Add(VerifyImageCommand.Create());

            Environment.ExitCode = 0;
            var config = new CommandLineConfiguration(rootCommand);
            var exitCode = await config.InvokeAsync(args);

            // Some commands set Environment.ExitCode directly
            if (Environment.ExitCode != 0)
            {
                exitCode = Environment.ExitCode;
                Environment.ExitCode = 0;
            }

            return new CommandResult(
                exitCode,
                stdOut.ToString(),
                stdErr.ToString());
        }
        finally
        {
            Console.SetOut(originalOut);
            Console.SetError(originalErr);
            ConsoleLock.Release();
        }
    }
}

public sealed record CommandResult(int ExitCode, string StdOut, string StdErr);
