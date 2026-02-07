using Secure.Sbom.Cli.Commands;
using System.CommandLine;

var rootCommand = new RootCommand("Sign and verify software artifacts with distributed trust");

rootCommand.Add(KeysCommand.Create());
rootCommand.Add(SignCommand.Create());
rootCommand.Add(VerifyCommand.Create());

var config = new CommandLineConfiguration(rootCommand);
return await config.InvokeAsync(args);
