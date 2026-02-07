using System.CommandLine;
using System.Globalization;
using Sigil.Trust;

namespace Sigil.Cli.Commands;

public static class TrustCreateCommand
{
    public static Command Create()
    {
        var nameOption = new Option<string>("--name") { Description = "Name for the trust bundle" };
        nameOption.Required = true;
        var descriptionOption = new Option<string?>("--description") { Description = "Description of the trust bundle" };
        var outputOption = new Option<string?>("-o") { Description = "Output file path (default: <name>.trust.json)" };

        var cmd = new Command("create", "Create a new unsigned trust bundle");
        cmd.Add(nameOption);
        cmd.Add(descriptionOption);
        cmd.Add(outputOption);

        cmd.SetAction(parseResult =>
        {
            var name = parseResult.GetValue(nameOption)!;
            var description = parseResult.GetValue(descriptionOption);
            var output = parseResult.GetValue(outputOption) ?? $"{name}.trust.json";

            var bundle = new TrustBundle
            {
                Metadata = new BundleMetadata
                {
                    Name = name,
                    Description = description,
                    Created = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ",
                        CultureInfo.InvariantCulture)
                }
            };

            var serializeResult = BundleSigner.Serialize(bundle);
            if (!serializeResult.IsSuccess)
            {
                Console.Error.WriteLine($"Failed to serialize bundle: {serializeResult.ErrorMessage}");
                return;
            }

            File.WriteAllText(output, serializeResult.Value);
            Console.WriteLine($"Created trust bundle: {output}");
            Console.WriteLine($"Name: {name}");
        });

        return cmd;
    }
}
