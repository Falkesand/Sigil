using System.CommandLine;
using Sigil.Graph;

namespace Sigil.Cli.Commands;

public static class GraphExportCommand
{
    public static Command Create()
    {
        var graphOption = new Option<string>("--graph") { Description = "Path to graph.json file" };
        graphOption.Required = true;
        var formatOption = new Option<string>("--format") { Description = "Export format: dot or json" };
        formatOption.Required = true;
        var outputOption = new Option<string?>("--output") { Description = "Output file path (default: stdout)" };

        var cmd = new Command("export", "Export a trust graph in DOT or JSON format");
        cmd.Add(graphOption);
        cmd.Add(formatOption);
        cmd.Add(outputOption);

        cmd.SetAction(async parseResult =>
        {
            var graphPath = parseResult.GetValue(graphOption)!;
            var format = parseResult.GetValue(formatOption)!;
            var output = parseResult.GetValue(outputOption);

            var json = await File.ReadAllTextAsync(graphPath);
            var deserializeResult = GraphSerializer.Deserialize(json);
            if (!deserializeResult.IsSuccess)
            {
                Console.Error.WriteLine($"Error: {deserializeResult.ErrorMessage}");
                Environment.ExitCode = 1;
                return;
            }

            var graph = deserializeResult.Value;

            string exported;
            switch (format.ToLowerInvariant())
            {
                case "dot":
                    exported = DotExporter.Export(graph);
                    break;
                case "json":
                    exported = JsonExporter.Export(graph);
                    break;
                default:
                    Console.Error.WriteLine($"Error: Unknown format '{format}'. Use 'dot' or 'json'.");
                    Environment.ExitCode = 1;
                    return;
            }

            if (output is not null)
            {
                await File.WriteAllTextAsync(output, exported);
                Console.WriteLine($"Exported graph to {output}");
            }
            else
            {
                Console.Write(exported);
            }
        });

        return cmd;
    }
}
