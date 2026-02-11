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

    public static async Task<T> RunWithEnvVarsAsync<T>(
        Dictionary<string, string?> envVars, Func<Task<T>> action)
    {
        await ConsoleLock.WaitAsync();

        var savedVars = new Dictionary<string, string?>();
        try
        {
            foreach (var (key, value) in envVars)
            {
                savedVars[key] = Environment.GetEnvironmentVariable(key);
                Environment.SetEnvironmentVariable(key, value);
            }

            return await action();
        }
        finally
        {
            foreach (var (key, value) in savedVars)
                Environment.SetEnvironmentVariable(key, value);

            ConsoleLock.Release();
        }
    }

    public static async Task<CommandResult> InvokeWithEnvVarsAsync(
        Dictionary<string, string?> envVars, params string[] args)
    {
        await ConsoleLock.WaitAsync();

        var savedVars = new Dictionary<string, string?>();
        try
        {
            foreach (var (key, value) in envVars)
            {
                savedVars[key] = Environment.GetEnvironmentVariable(key);
                Environment.SetEnvironmentVariable(key, value);
            }

            return await InvokeLockedAsync(args);
        }
        finally
        {
            foreach (var (key, value) in savedVars)
                Environment.SetEnvironmentVariable(key, value);

            ConsoleLock.Release();
        }
    }

    public static async Task<CommandResult> InvokeAsync(params string[] args)
    {
        await ConsoleLock.WaitAsync();

        try
        {
            return await InvokeLockedAsync(args);
        }
        finally
        {
            ConsoleLock.Release();
        }
    }

    private static async Task<CommandResult> InvokeLockedAsync(string[] args)
    {
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
            trustCommand.Add(TrustIdentityAddCommand.Create());
            trustCommand.Add(TrustIdentityRemoveCommand.Create());
            rootCommand.Add(trustCommand);
            rootCommand.Add(DiscoverCommand.Create());
            rootCommand.Add(TimestampCommand.Create());
            rootCommand.Add(AttestCommand.Create());
            rootCommand.Add(VerifyAttestationCommand.Create());
            rootCommand.Add(LogCommand.Create());
            rootCommand.Add(GitCommand.Create());
            rootCommand.Add(SignImageCommand.Create());
            rootCommand.Add(VerifyImageCommand.Create());
            rootCommand.Add(SignManifestCommand.Create());
            rootCommand.Add(VerifyManifestCommand.Create());
            rootCommand.Add(SignArchiveCommand.Create());
            rootCommand.Add(VerifyArchiveCommand.Create());
            rootCommand.Add(CredentialCommand.Create());

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
        }
    }
}

public sealed record CommandResult(int ExitCode, string StdOut, string StdErr);
