using System.CommandLine;
using Sigil.Transparency;

namespace Sigil.Cli.Commands;

public static class LogVerifyCommand
{
    public static Command Create()
    {
        var logOption = new Option<string?>("--log") { Description = "Path to log file (default: .sigil.log.jsonl)" };
        var checkpointOption = new Option<string?>("--checkpoint") { Description = "Path to checkpoint file" };

        var cmd = new Command("verify", "Verify transparency log integrity");
        cmd.Add(logOption);
        cmd.Add(checkpointOption);

        cmd.SetAction(parseResult =>
        {
            var logPath = parseResult.GetValue(logOption) ?? ".sigil.log.jsonl";
            var checkpointPath = parseResult.GetValue(checkpointOption);

            var log = new TransparencyLog(logPath, checkpointPath);
            var result = log.Verify();

            if (!result.IsSuccess)
            {
                Console.Error.WriteLine($"Error: {result.ErrorMessage}");
                Environment.ExitCode = 1;
                return;
            }

            var verification = result.Value;
            Console.WriteLine($"Entries:     {verification.EntryCount}");
            Console.WriteLine($"Valid:       {verification.ValidEntries}");
            Console.WriteLine($"Root hash:   {verification.ComputedRootHash}");

            if (verification.CheckpointRootHash is not null)
                Console.WriteLine($"Checkpoint:  {(verification.CheckpointMatch ? "MATCH" : "MISMATCH")}");

            if (verification.AllEntriesValid && verification.CheckpointMatch)
            {
                Console.WriteLine("All entries valid. Log integrity verified.");
            }
            else
            {
                if (!verification.AllEntriesValid)
                {
                    Console.Error.WriteLine("INTEGRITY VIOLATION: Invalid entries detected.");
                    if (verification.InvalidIndices is not null)
                    {
                        foreach (var idx in verification.InvalidIndices)
                            Console.Error.WriteLine($"  Invalid index: {idx}");
                    }
                }

                if (!verification.CheckpointMatch)
                    Console.Error.WriteLine("CHECKPOINT MISMATCH: Root hash does not match checkpoint.");

                Environment.ExitCode = 1;
            }
        });

        return cmd;
    }
}
