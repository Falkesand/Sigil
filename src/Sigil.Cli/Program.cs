using Sigil.Cli.Commands;
using System.CommandLine;

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
rootCommand.Add(trustCommand);
rootCommand.Add(DiscoverCommand.Create());
rootCommand.Add(TimestampCommand.Create());

var config = new CommandLineConfiguration(rootCommand);
return await config.InvokeAsync(args);
