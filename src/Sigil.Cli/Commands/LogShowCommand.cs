using System.CommandLine;
using Sigil.Transparency;

namespace Sigil.Cli.Commands;

public static class LogShowCommand
{
    public static Command Create()
    {
        var logOption = new Option<string?>("--log") { Description = "Path to log file (default: .sigil.log.jsonl)" };
        var limitOption = new Option<int?>("--limit") { Description = "Maximum number of entries to show" };
        var offsetOption = new Option<int?>("--offset") { Description = "Number of entries to skip" };

        var cmd = new Command("show", "Display transparency log entries");
        cmd.Add(logOption);
        cmd.Add(limitOption);
        cmd.Add(offsetOption);

        cmd.SetAction(parseResult =>
        {
            var logPath = parseResult.GetValue(logOption) ?? ".sigil.log.jsonl";
            var limit = parseResult.GetValue(limitOption);
            var offset = parseResult.GetValue(offsetOption);

            var log = new TransparencyLog(logPath);
            var result = log.ReadEntries(limit: limit, offset: offset);

            if (!result.IsSuccess)
            {
                Console.Error.WriteLine($"Error: {result.ErrorMessage}");
                Environment.ExitCode = 1;
                return;
            }

            var entries = result.Value;
            Console.WriteLine($"Showing {entries.Count} entries.");

            foreach (var entry in entries)
            {
                Console.WriteLine($"[{entry.Index}] {entry.Timestamp}");
                Console.WriteLine($"  Artifact:  {entry.ArtifactName}");
                Console.WriteLine($"  Digest:    {entry.ArtifactDigest}");
                Console.WriteLine($"  Key:       {entry.KeyId}");
                Console.WriteLine($"  Algorithm: {entry.Algorithm}");
                Console.WriteLine($"  Sig hash:  {entry.SignatureDigest}");
                Console.WriteLine($"  Leaf hash: {entry.LeafHash}");
                if (entry.Label is not null)
                    Console.WriteLine($"  Label:     {entry.Label}");
            }
        });

        return cmd;
    }
}
