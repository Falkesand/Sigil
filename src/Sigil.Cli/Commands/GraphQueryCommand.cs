using System.CommandLine;
using Sigil.Graph;

namespace Sigil.Cli.Commands;

public static class GraphQueryCommand
{
    public static Command Create()
    {
        var graphOption = new Option<string>("--graph") { Description = "Path to graph.json file" };
        graphOption.Required = true;
        var keyOption = new Option<string?>("--key") { Description = "Key fingerprint for queries" };
        var artifactOption = new Option<string?>("--artifact") { Description = "Artifact name for queries" };
        var fromOption = new Option<string?>("--from") { Description = "Start node ID for path query" };
        var toOption = new Option<string?>("--to") { Description = "End node ID for path query" };
        var reachOption = new Option<bool>("--reach") { Description = "Find all reachable nodes from key" };
        var chainOption = new Option<bool>("--chain") { Description = "Show trust chain for artifact" };
        var signedByOption = new Option<bool>("--signed-by") { Description = "Show artifacts signed by key" };
        var revokedOption = new Option<bool>("--revoked") { Description = "Analyze revoked key impact" };
        var impactOption = new Option<bool>("--impact") { Description = "Show impact analysis (use with --revoked)" };
        var pathOption = new Option<bool>("--path") { Description = "Find shortest path between nodes" };

        var cmd = new Command("query", "Query a trust graph");
        cmd.Add(graphOption);
        cmd.Add(keyOption);
        cmd.Add(artifactOption);
        cmd.Add(fromOption);
        cmd.Add(toOption);
        cmd.Add(reachOption);
        cmd.Add(chainOption);
        cmd.Add(signedByOption);
        cmd.Add(revokedOption);
        cmd.Add(impactOption);
        cmd.Add(pathOption);

        cmd.SetAction(async parseResult =>
        {
            var graphPath = parseResult.GetValue(graphOption)!;
            var key = parseResult.GetValue(keyOption);
            var artifact = parseResult.GetValue(artifactOption);
            var from = parseResult.GetValue(fromOption);
            var to = parseResult.GetValue(toOption);
            var reach = parseResult.GetValue(reachOption);
            var chain = parseResult.GetValue(chainOption);
            var signedBy = parseResult.GetValue(signedByOption);
            var revoked = parseResult.GetValue(revokedOption);
            var impact = parseResult.GetValue(impactOption);
            var path = parseResult.GetValue(pathOption);

            if (!File.Exists(graphPath))
            {
                Console.Error.WriteLine($"Error: Graph file not found: {graphPath}");
                Environment.ExitCode = 1;
                return;
            }

            var json = await File.ReadAllTextAsync(graphPath);
            var deserializeResult = GraphSerializer.Deserialize(json);
            if (!deserializeResult.IsSuccess)
            {
                Console.Error.WriteLine($"Error: {deserializeResult.ErrorMessage}");
                Environment.ExitCode = 1;
                return;
            }

            var graph = deserializeResult.Value;

            if (reach && key is not null)
            {
                var result = GraphQuery.Reachable(graph, $"key:{key}");
                if (!result.IsSuccess)
                {
                    Console.Error.WriteLine($"Error: {result.ErrorMessage}");
                    Environment.ExitCode = 1;
                    return;
                }
                Console.WriteLine($"Reachable from key:{key}:");
                foreach (var nodeId in result.Value)
                    Console.WriteLine($"  {nodeId}");
            }
            else if (chain && artifact is not null)
            {
                var result = GraphQuery.TrustChain(graph, $"artifact:{artifact}");
                if (!result.IsSuccess)
                {
                    Console.Error.WriteLine($"Error: {result.ErrorMessage}");
                    Environment.ExitCode = 1;
                    return;
                }
                Console.WriteLine($"Trust chain for artifact:{artifact}:");
                foreach (var nodeId in result.Value)
                    Console.WriteLine($"  {nodeId}");
            }
            else if (signedBy && key is not null)
            {
                var result = GraphQuery.SignedBy(graph, $"key:{key}");
                if (!result.IsSuccess)
                {
                    Console.Error.WriteLine($"Error: {result.ErrorMessage}");
                    Environment.ExitCode = 1;
                    return;
                }
                Console.WriteLine($"Artifacts signed by key:{key}:");
                foreach (var nodeId in result.Value)
                    Console.WriteLine($"  {nodeId}");
            }
            else if (revoked && impact)
            {
                var affectedArtifacts = GraphQuery.RevokedImpact(graph);
                Console.WriteLine("Revoked key impact analysis:");
                if (affectedArtifacts.Count == 0)
                {
                    Console.WriteLine("  No affected artifacts.");
                }
                else
                {
                    foreach (var nodeId in affectedArtifacts)
                        Console.WriteLine($"  {nodeId}");
                }
            }
            else if (path && from is not null && to is not null)
            {
                var result = GraphQuery.ShortestPath(graph, from, to);
                if (!result.IsSuccess)
                {
                    Console.Error.WriteLine($"Error: {result.ErrorMessage}");
                    Environment.ExitCode = 1;
                    return;
                }
                if (result.Value.Count == 0)
                {
                    Console.WriteLine($"No path from {from} to {to}.");
                }
                else
                {
                    Console.WriteLine($"Shortest path from {from} to {to}:");
                    Console.WriteLine($"  {string.Join(" -> ", result.Value)}");
                }
            }
            else
            {
                Console.Error.WriteLine("Error: Specify a valid query combination. Use --help for options.");
                Environment.ExitCode = 1;
            }
        });

        return cmd;
    }
}
