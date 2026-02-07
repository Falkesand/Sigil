using System.CommandLine;
using Sigil.Keys;
using Sigil.Signing;

namespace Sigil.Cli.Commands;

public static class VerifyCommand
{
    public static Command Create()
    {
        var artifactArg = new Argument<FileInfo>("artifact") { Description = "Path to the artifact to verify" };
        var signatureOption = new Option<string?>("--signature") { Description = "Path to the signature file (default: <artifact>.sig.json)" };

        var cmd = new Command("verify", "Verify the signature of an artifact");
        cmd.Add(artifactArg);
        cmd.Add(signatureOption);

        cmd.SetAction(parseResult =>
        {
            var artifact = parseResult.GetValue(artifactArg)!;
            var signaturePath = parseResult.GetValue(signatureOption);

            if (!artifact.Exists)
            {
                Console.Error.WriteLine($"Artifact not found: {artifact.FullName}");
                return;
            }

            signaturePath ??= artifact.FullName + ".sig.json";
            if (!File.Exists(signaturePath))
            {
                Console.Error.WriteLine($"Signature file not found: {signaturePath}");
                return;
            }

            var sigJson = File.ReadAllText(signaturePath);
            var envelope = ArtifactSigner.Deserialize(sigJson);
            var store = KeyStore.Default();

            var result = SignatureValidator.Verify(artifact.FullName, envelope, store);

            if (!result.ArtifactDigestMatch)
            {
                Console.Error.WriteLine("FAILED: Artifact digest mismatch — file has been modified.");
                return;
            }

            Console.WriteLine($"Artifact: {artifact.Name}");
            Console.WriteLine("Digests: MATCH");

            foreach (var sig in result.Signatures)
            {
                var status = sig.IsValid ? "VERIFIED" : "FAILED";
                var label = sig.Label is not null ? $" ({sig.Label})" : "";
                Console.WriteLine($"  [{status}] {sig.KeyId}{label}");
                if (sig.Error is not null)
                    Console.WriteLine($"           {sig.Error}");
            }

            if (result.AllSignaturesValid)
                Console.WriteLine("\nAll signatures VERIFIED.");
            else if (result.AnySignatureValid)
                Console.WriteLine("\nSome signatures verified, some failed.");
            else
                Console.WriteLine("\nNo valid signatures found.");
        });

        return cmd;
    }
}
