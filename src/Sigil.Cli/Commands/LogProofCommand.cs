using System.CommandLine;
using Sigil.Transparency;

namespace Sigil.Cli.Commands;

public static class LogProofCommand
{
    public static Command Create()
    {
        var logOption = new Option<string?>("--log") { Description = "Path to log file (default: .sigil.log.jsonl)" };
        var indexOption = new Option<int?>("--index") { Description = "Leaf index for inclusion proof" };
        var oldSizeOption = new Option<int?>("--old-size") { Description = "Old tree size for consistency proof" };

        var cmd = new Command("proof", "Generate inclusion or consistency proof");
        cmd.Add(logOption);
        cmd.Add(indexOption);
        cmd.Add(oldSizeOption);

        cmd.SetAction(parseResult =>
        {
            var logPath = parseResult.GetValue(logOption) ?? ".sigil.log.jsonl";
            var index = parseResult.GetValue(indexOption);
            var oldSize = parseResult.GetValue(oldSizeOption);

            if (!oldSize.HasValue && !index.HasValue)
            {
                Console.Error.WriteLine("Error: --index is required for inclusion proofs. Use --old-size for consistency proofs.");
                Environment.ExitCode = 1;
                return;
            }

            var log = new TransparencyLog(logPath);

            if (oldSize.HasValue)
            {
                // Consistency proof
                var result = log.GetConsistencyProof(oldSize.Value);
                if (!result.IsSuccess)
                {
                    Console.Error.WriteLine($"Error: {result.ErrorMessage}");
                    Environment.ExitCode = 1;
                    return;
                }

                var proof = result.Value;
                Console.WriteLine("Consistency proof:");
                Console.WriteLine($"  Old size:  {proof.OldSize}");
                Console.WriteLine($"  New size:  {proof.NewSize}");
                Console.WriteLine($"  Old root:  {proof.OldRootHash}");
                Console.WriteLine($"  New root:  {proof.NewRootHash}");
                Console.WriteLine($"  Hashes:    {proof.Hashes.Count}");

                var verified = MerkleTree.VerifyConsistencyProof(proof);
                Console.WriteLine(verified ? "Consistency proof VERIFIED." : "Consistency proof FAILED.");

                if (!verified)
                    Environment.ExitCode = 1;
            }
            else
            {
                // Inclusion proof — index.HasValue is guaranteed by check above
                var result = log.GetInclusionProof(index!.Value);
                if (!result.IsSuccess)
                {
                    Console.Error.WriteLine($"Error: {result.ErrorMessage}");
                    Environment.ExitCode = 1;
                    return;
                }

                var proof = result.Value;
                Console.WriteLine("Inclusion proof:");
                Console.WriteLine($"  Leaf index: {proof.LeafIndex}");
                Console.WriteLine($"  Tree size:  {proof.TreeSize}");
                Console.WriteLine($"  Root hash:  {proof.RootHash}");
                Console.WriteLine($"  Hashes:     {proof.Hashes.Count}");

                // Verify by reading the leaf hash from the log
                var entriesResult = log.ReadEntries(limit: 1, offset: index.Value);
                if (entriesResult.IsSuccess && entriesResult.Value.Count > 0)
                {
                    var leafHash = Convert.FromHexString(entriesResult.Value[0].LeafHash);
                    var verified = MerkleTree.VerifyInclusionProof(proof, leafHash);
                    Console.WriteLine(verified ? "Inclusion proof VERIFIED." : "Inclusion proof FAILED.");

                    if (!verified)
                        Environment.ExitCode = 1;
                }
            }
        });

        return cmd;
    }
}
