using System.CommandLine;
using Sigil.Signing;
using Sigil.Timestamping;

namespace Sigil.Cli.Commands;

public static class TimestampCommand
{
    public static Command Create()
    {
        var envelopeArg = new Argument<FileInfo>("envelope") { Description = "Path to the signature envelope" };
        var tsaOption = new Option<string>("--tsa") { Description = "TSA URL for RFC 3161 timestamping" };
        tsaOption.Required = true;
        var indexOption = new Option<int?>("--index") { Description = "Specific signature index to timestamp (default: all without tokens)" };

        var cmd = new Command("timestamp", "Apply RFC 3161 timestamp tokens to signature entries");
        cmd.Add(envelopeArg);
        cmd.Add(tsaOption);
        cmd.Add(indexOption);

        cmd.SetAction(async parseResult =>
        {
            var envelopeFile = parseResult.GetValue(envelopeArg)!;
            var tsaUrl = parseResult.GetValue(tsaOption)!;
            var index = parseResult.GetValue(indexOption);

            if (!envelopeFile.Exists)
            {
                Console.Error.WriteLine($"Envelope not found: {envelopeFile.FullName}");
                return;
            }

            var json = File.ReadAllText(envelopeFile.FullName);
            SignatureEnvelope envelope;
            try
            {
                envelope = ArtifactSigner.Deserialize(json);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Failed to parse envelope: {ex.Message}");
                return;
            }

            if (envelope.Signatures.Count == 0)
            {
                Console.Error.WriteLine("Envelope contains no signatures.");
                return;
            }

            if (!Uri.TryCreate(tsaUrl, UriKind.Absolute, out var tsaUri))
            {
                Console.Error.WriteLine($"Invalid TSA URL: {tsaUrl}");
                return;
            }

            using var client = new TsaClient();
            var updated = false;

            if (index is not null)
            {
                if (index.Value < 0 || index.Value >= envelope.Signatures.Count)
                {
                    Console.Error.WriteLine($"Invalid index: {index.Value}. Envelope has {envelope.Signatures.Count} signature(s).");
                    return;
                }

                if (envelope.Signatures[index.Value].TimestampToken is not null)
                {
                    Console.Error.WriteLine($"Signature at index {index.Value} is already timestamped.");
                    return;
                }

                var result = await TimestampApplier.ApplyAsync(
                    envelope.Signatures[index.Value], tsaUri, client).ConfigureAwait(false);

                if (result.IsSuccess)
                {
                    envelope.Signatures[index.Value] = result.Value;
                    Console.WriteLine($"[{index.Value}] Timestamped: {GetTimestampDisplay(result.Value)}");
                    updated = true;
                }
                else
                {
                    Console.Error.WriteLine($"[{index.Value}] Failed: {result.ErrorMessage}");
                }
            }
            else
            {
                for (var i = 0; i < envelope.Signatures.Count; i++)
                {
                    if (envelope.Signatures[i].TimestampToken is not null)
                    {
                        Console.WriteLine($"[{i}] Skipped (already timestamped)");
                        continue;
                    }

                    var result = await TimestampApplier.ApplyAsync(
                        envelope.Signatures[i], tsaUri, client).ConfigureAwait(false);

                    if (result.IsSuccess)
                    {
                        envelope.Signatures[i] = result.Value;
                        Console.WriteLine($"[{i}] Timestamped: {GetTimestampDisplay(result.Value)}");
                        updated = true;
                    }
                    else
                    {
                        Console.Error.WriteLine($"[{i}] Failed: {result.ErrorMessage}");
                    }
                }
            }

            if (updated)
            {
                var outputJson = ArtifactSigner.Serialize(envelope);
                File.WriteAllText(envelopeFile.FullName, outputJson);
                Console.WriteLine($"Updated: {envelopeFile.FullName}");
            }
        });

        return cmd;
    }

    private static string GetTimestampDisplay(SignatureEntry entry)
    {
        if (entry.TimestampToken is null)
            return "no token";

        var sigBytes = Convert.FromBase64String(entry.Value);
        var info = TimestampValidator.Validate(entry.TimestampToken, sigBytes);
        return info.IsValid
            ? $"{info.Timestamp:yyyy-MM-ddTHH:mm:ssZ} (verified)"
            : $"INVALID ({info.Error})";
    }
}
