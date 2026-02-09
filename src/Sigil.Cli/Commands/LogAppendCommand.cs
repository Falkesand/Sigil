using System.CommandLine;
using System.Text.Json;
using Sigil.Signing;
using Sigil.Transparency;

namespace Sigil.Cli.Commands;

public static class LogAppendCommand
{
    public static Command Create()
    {
        var envelopeArg = new Argument<string>("envelope") { Description = "Path to signature envelope (.sig.json)" };
        var logOption = new Option<string?>("--log") { Description = "Path to log file (default: .sigil.log.jsonl)" };
        var indexOption = new Option<int>("--signature-index") { Description = "Signature index within envelope (default: 0)" };

        var cmd = new Command("append", "Append a signing event to the transparency log");
        cmd.Add(envelopeArg);
        cmd.Add(logOption);
        cmd.Add(indexOption);

        cmd.SetAction(parseResult =>
        {
            var envelopePath = parseResult.GetValue(envelopeArg)!;
            var logPath = parseResult.GetValue(logOption) ?? ".sigil.log.jsonl";
            var signatureIndex = parseResult.GetValue(indexOption);

            if (!File.Exists(envelopePath))
            {
                Console.Error.WriteLine($"Envelope not found: {envelopePath}");
                Environment.ExitCode = 1;
                return;
            }

            var json = File.ReadAllText(envelopePath);
            SignatureEnvelope? envelope;
            try
            {
                envelope = JsonSerializer.Deserialize<SignatureEnvelope>(json);
            }
            catch (JsonException ex)
            {
                Console.Error.WriteLine($"Invalid envelope: {ex.Message}");
                Environment.ExitCode = 1;
                return;
            }

            if (envelope is null)
            {
                Console.Error.WriteLine("Failed to parse envelope.");
                Environment.ExitCode = 1;
                return;
            }

            var log = new TransparencyLog(logPath);
            var result = log.Append(envelope, signatureIndex);

            if (!result.IsSuccess)
            {
                Console.Error.WriteLine($"Error: {result.ErrorMessage}");
                Environment.ExitCode = 1;
                return;
            }

            var entry = result.Value;
            Console.WriteLine($"Appended entry #{entry.Index}");
            Console.WriteLine($"  Artifact: {entry.ArtifactName}");
            Console.WriteLine($"  Key:      {entry.KeyId}");
            Console.WriteLine($"  Leaf:     {entry.LeafHash}");
        });

        return cmd;
    }
}
