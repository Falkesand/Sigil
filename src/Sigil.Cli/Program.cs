using Sigil.Cli.Commands;
using System.CommandLine;

// Intercept git-sign before System.CommandLine — git passes GPG-compat args
// that don't conform to System.CommandLine conventions.
if (GitSignProgram.ShouldIntercept(args))
{
    return await GitSignProgram.RunAsync(args, Console.In, Console.Out, Console.Error);
}

var rootCommand = new RootCommand("Sign and verify software artifacts with distributed trust");

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

var config = new CommandLineConfiguration(rootCommand);
return await config.InvokeAsync(args);
