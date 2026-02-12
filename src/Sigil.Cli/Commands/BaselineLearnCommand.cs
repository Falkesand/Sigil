using System.CommandLine;
using System.Text.Json;
using Sigil.Anomaly;
using Sigil.Signing;

namespace Sigil.Cli.Commands;

public static class BaselineLearnCommand
{
    public static Command Create()
    {
        var scanOption = new Option<DirectoryInfo>("--scan") { Description = "Directory with *.sig.json files to learn from" };
        scanOption.Required = true;
        var outputOption = new Option<string?>("--output") { Description = "Output path for baseline file (default: <scan-dir>/.sigil.baseline.json)" };

        var cmd = new Command("learn", "Learn signing patterns from existing signatures");
        cmd.Add(scanOption);
        cmd.Add(outputOption);

        cmd.SetAction(async parseResult =>
        {
            var scanDir = parseResult.GetValue(scanOption)!;
            var outputPath = parseResult.GetValue(outputOption);

            if (!scanDir.Exists)
            {
                Console.Error.WriteLine($"Directory not found: {scanDir.FullName}");
                Environment.ExitCode = 1;
                return;
            }

            // Discover *.sig.json files (not manifest or archive sigs)
            var sigFiles = Directory.GetFiles(scanDir.FullName, "*.sig.json")
                .Where(f => !f.EndsWith(".manifest.sig.json", StringComparison.OrdinalIgnoreCase)
                         && !f.EndsWith(".archive.sig.json", StringComparison.OrdinalIgnoreCase))
                .ToList();

            // Deserialize envelopes
            var envelopes = new List<SignatureEnvelope>();
            foreach (var file in sigFiles)
            {
                try
                {
                    var json = await File.ReadAllTextAsync(file);
                    var envelope = ArtifactSigner.Deserialize(json);
                    envelopes.Add(envelope);
                }
                catch (JsonException)
                {
                    Console.Error.WriteLine($"Warning: Skipping invalid signature file: {Path.GetFileName(file)}");
                }
            }

            // Learn baseline
            var result = BaselineLearner.Learn(envelopes);
            if (!result.IsSuccess)
            {
                Console.Error.WriteLine($"Error learning baseline: {result.ErrorMessage}");
                Environment.ExitCode = 1;
                return;
            }

            // Write baseline
            outputPath ??= Path.Combine(scanDir.FullName, ".sigil.baseline.json");
            var baselineJson = BaselineSerializer.Serialize(result.Value);
            await File.WriteAllTextAsync(outputPath, baselineJson);

            Console.WriteLine($"Baseline learned from {envelopes.Count} signature file(s) ({result.Value.SampleCount} signature entries).");
            Console.WriteLine($"Baseline written to: {outputPath}");
        });

        return cmd;
    }
}
