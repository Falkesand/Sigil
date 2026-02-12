using System.CommandLine;
using Sigil.Graph;

namespace Sigil.Cli.Commands;

public static class GraphBuildCommand
{
    public static Command Create()
    {
        var scanOption = new Option<string>("--scan") { Description = "Directory to scan for signature envelopes, trust bundles, and attestations" };
        scanOption.Required = true;
        var outputOption = new Option<string?>("--output") { Description = "Output file path for the graph (default: graph.json)" };

        var cmd = new Command("build", "Build a trust graph from artifacts in a directory");
        cmd.Add(scanOption);
        cmd.Add(outputOption);

        cmd.SetAction(async parseResult =>
        {
            var scanDir = parseResult.GetValue(scanOption)!;
            var output = parseResult.GetValue(outputOption);
            var outputPath = output ?? "graph.json";

            var graph = new TrustGraph();
            var scanResult = GraphBuilder.ScanDirectory(graph, scanDir);

            if (!scanResult.IsSuccess)
            {
                Console.Error.WriteLine($"Error: {scanResult.ErrorMessage}");
                Environment.ExitCode = 1;
                return;
            }

            Console.WriteLine($"Ingested {scanResult.Value} file(s): {graph.NodeCount} nodes, {graph.EdgeCount} edges.");

            var serializeResult = GraphSerializer.Serialize(graph);
            if (!serializeResult.IsSuccess)
            {
                Console.Error.WriteLine($"Error serializing graph: {serializeResult.ErrorMessage}");
                Environment.ExitCode = 1;
                return;
            }

            await File.WriteAllTextAsync(outputPath, serializeResult.Value);
            Console.WriteLine($"Graph written to {outputPath}");
        });

        return cmd;
    }
}
