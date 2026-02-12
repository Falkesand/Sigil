using System.CommandLine;
using System.Text;
using Sigil.Graph;
using Sigil.Keys;

namespace Sigil.Cli.Commands;

public static class ImpactCommand
{
    public static Command Create()
    {
        var fingerprintOption = new Option<string?>("--fingerprint") { Description = "Key fingerprint to analyze (sha256:...)" };
        var keyOption = new Option<string?>("--key") { Description = "PEM file path — compute fingerprint from SPKI" };
        var scanOption = new Option<string?>("--scan") { Description = "Directory to scan for building the graph" };
        var graphOption = new Option<string?>("--graph") { Description = "Path to pre-built graph.json file" };
        var formatOption = new Option<string?>("--format") { Description = "Output format: text or json (default: text)" };
        var outputOption = new Option<string?>("--output") { Description = "Write output to file instead of stdout" };

        var cmd = new Command("impact", "Analyze the impact of a key compromise");
        cmd.Add(fingerprintOption);
        cmd.Add(keyOption);
        cmd.Add(scanOption);
        cmd.Add(graphOption);
        cmd.Add(formatOption);
        cmd.Add(outputOption);

        cmd.SetAction(async parseResult =>
        {
            var fingerprint = parseResult.GetValue(fingerprintOption);
            var keyPath = parseResult.GetValue(keyOption);
            var scanDir = parseResult.GetValue(scanOption);
            var graphPath = parseResult.GetValue(graphOption);
            var format = parseResult.GetValue(formatOption) ?? "text";
            var outputPath = parseResult.GetValue(outputOption);

            // Validate: exactly one of --fingerprint or --key
            if (fingerprint is not null && keyPath is not null)
            {
                Console.Error.WriteLine("Error: Specify either --fingerprint or --key, not both.");
                Environment.ExitCode = 1;
                return;
            }

            if (fingerprint is null && keyPath is null)
            {
                Console.Error.WriteLine("Error: Specify --fingerprint or --key to identify the key.");
                Environment.ExitCode = 1;
                return;
            }

            // Validate: exactly one of --scan or --graph
            if (scanDir is not null && graphPath is not null)
            {
                Console.Error.WriteLine("Error: Specify either --scan or --graph, not both.");
                Environment.ExitCode = 1;
                return;
            }

            if (scanDir is null && graphPath is null)
            {
                Console.Error.WriteLine("Error: Specify --scan or --graph to provide the trust graph.");
                Environment.ExitCode = 1;
                return;
            }

            // Validate format
            if (format is not "text" and not "json")
            {
                Console.Error.WriteLine("Error: Unknown format. Use 'text' or 'json'.");
                Environment.ExitCode = 1;
                return;
            }

            // Resolve fingerprint from PEM if --key provided
            if (keyPath is not null)
            {
                if (!File.Exists(keyPath))
                {
                    Console.Error.WriteLine($"Error: PEM file not found: {keyPath}");
                    Environment.ExitCode = 1;
                    return;
                }

                try
                {
                    var pem = await File.ReadAllTextAsync(keyPath);
                    var spki = ExtractSpkiFromPem(pem);
                    fingerprint = KeyFingerprint.Compute(spki).Value;
                }
#pragma warning disable CA1031 // Do not catch general exception types — CLI reports user-facing errors
                catch (Exception ex)
#pragma warning restore CA1031
                {
                    Console.Error.WriteLine($"Error: Failed to read PEM file: {ex.Message}");
                    Environment.ExitCode = 1;
                    return;
                }
            }

            // Build or load graph
            TrustGraph graph;
            if (scanDir is not null)
            {
                if (!Directory.Exists(scanDir))
                {
                    Console.Error.WriteLine($"Error: Directory not found: {scanDir}");
                    Environment.ExitCode = 1;
                    return;
                }

                graph = new TrustGraph();
                var scanResult = GraphBuilder.ScanDirectory(graph, scanDir);
                if (!scanResult.IsSuccess)
                {
                    Console.Error.WriteLine($"Error: {scanResult.ErrorMessage}");
                    Environment.ExitCode = 1;
                    return;
                }
            }
            else
            {
                if (!File.Exists(graphPath))
                {
                    Console.Error.WriteLine($"Error: Graph file not found: {graphPath}");
                    Environment.ExitCode = 1;
                    return;
                }

                var json = await File.ReadAllTextAsync(graphPath!);
                var deserializeResult = GraphSerializer.Deserialize(json);
                if (!deserializeResult.IsSuccess)
                {
                    Console.Error.WriteLine($"Error: {deserializeResult.ErrorMessage}");
                    Environment.ExitCode = 1;
                    return;
                }

                graph = deserializeResult.Value;
            }

            // Run analysis
            var keyId = $"key:{fingerprint}";
            var analyzeResult = ImpactAnalyzer.Analyze(graph, keyId);
            if (!analyzeResult.IsSuccess)
            {
                Console.Error.WriteLine($"Error: {analyzeResult.ErrorMessage}");
                Environment.ExitCode = 1;
                return;
            }

            // Format output
            var output = format == "json"
                ? ImpactAnalyzer.FormatJson(analyzeResult.Value)
                : ImpactAnalyzer.FormatText(analyzeResult.Value);

            // Write output
            if (outputPath is not null)
            {
                await File.WriteAllTextAsync(outputPath, output);
                Console.WriteLine($"Impact report written to {outputPath}");
            }
            else
            {
                Console.Write(output);
            }
        });

        return cmd;
    }

    /// <summary>
    /// Extracts the DER-encoded SPKI bytes from a public key PEM file.
    /// The base64 body between BEGIN PUBLIC KEY / END PUBLIC KEY is the SPKI DER.
    /// </summary>
    private static byte[] ExtractSpkiFromPem(string pem)
    {
        var sb = new StringBuilder();
        var foundPublicKey = false;
        foreach (var line in pem.AsSpan().EnumerateLines())
        {
            var trimmed = line.Trim();
            if (trimmed.StartsWith("-----BEGIN PUBLIC KEY-----", StringComparison.Ordinal))
            {
                foundPublicKey = true;
                continue;
            }
            if (trimmed.StartsWith("-----", StringComparison.Ordinal))
                continue;
            if (trimmed.IsEmpty)
                continue;
            sb.Append(trimmed);
        }

        if (!foundPublicKey)
            throw new FormatException("PEM file must contain a PUBLIC KEY block. Provide a public key file, not a private key or certificate.");

        if (sb.Length == 0)
            throw new FormatException("PEM file contains no key data.");

        return Convert.FromBase64String(sb.ToString());
    }
}
