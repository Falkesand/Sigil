using System.CommandLine;
using Sigil.Transparency;

namespace Sigil.Cli.Commands;

public static class LogSearchCommand
{
    public static Command Create()
    {
        var logOption = new Option<string?>("--log") { Description = "Path to log file (default: .sigil.log.jsonl)" };
        var keyOption = new Option<string?>("--key") { Description = "Search by key fingerprint" };
        var artifactOption = new Option<string?>("--artifact") { Description = "Search by artifact name" };
        var digestOption = new Option<string?>("--digest") { Description = "Search by signature or artifact digest" };

        var cmd = new Command("search", "Search transparency log entries");
        cmd.Add(logOption);
        cmd.Add(keyOption);
        cmd.Add(artifactOption);
        cmd.Add(digestOption);

        cmd.SetAction(parseResult =>
        {
            var logPath = parseResult.GetValue(logOption) ?? ".sigil.log.jsonl";
            var key = parseResult.GetValue(keyOption);
            var artifact = parseResult.GetValue(artifactOption);
            var digest = parseResult.GetValue(digestOption);

            if (key is null && artifact is null && digest is null)
            {
                Console.Error.WriteLine("At least one search filter is required: --key, --artifact, or --digest");
                Environment.ExitCode = 1;
                return;
            }

            var log = new TransparencyLog(logPath);
            var result = log.Search(keyId: key, artifactName: artifact, digest: digest);

            if (!result.IsSuccess)
            {
                Console.Error.WriteLine($"Error: {result.ErrorMessage}");
                Environment.ExitCode = 1;
                return;
            }

            var entries = result.Value;
            Console.WriteLine($"Found {entries.Count} entries.");

            foreach (var entry in entries)
            {
                Console.WriteLine($"  [{entry.Index}] {entry.ArtifactName} — {entry.KeyId} ({entry.Algorithm})");
                if (entry.Label is not null)
                    Console.WriteLine($"         Label: {entry.Label}");
            }
        });

        return cmd;
    }
}
