using System.CommandLine;
using Sigil.Crypto;
using Sigil.Keys;
using Sigil.Signing;

namespace Sigil.Cli.Commands;

public static class SignCommand
{
    public static Command Create()
    {
        var artifactArg = new Argument<FileInfo>("artifact") { Description = "Path to the artifact to sign" };
        var keyOption = new Option<string?>("--key") { Description = "Path to a private key PEM file (ephemeral if omitted)" };
        var outputOption = new Option<string?>("--output") { Description = "Output path for the signature file" };
        var labelOption = new Option<string?>("--label") { Description = "Label for this signature" };
        var passphraseOption = new Option<string?>("--passphrase") { Description = "Passphrase if the signing key is encrypted" };

        var cmd = new Command("sign", "Sign an artifact and produce a detached signature envelope");
        cmd.Add(artifactArg);
        cmd.Add(keyOption);
        cmd.Add(outputOption);
        cmd.Add(labelOption);
        cmd.Add(passphraseOption);

        cmd.SetAction(parseResult =>
        {
            var artifact = parseResult.GetValue(artifactArg)!;
            var keyPath = parseResult.GetValue(keyOption);
            var output = parseResult.GetValue(outputOption);
            var label = parseResult.GetValue(labelOption);
            var passphrase = parseResult.GetValue(passphraseOption);

            if (!artifact.Exists)
            {
                Console.Error.WriteLine($"Artifact not found: {artifact.FullName}");
                return;
            }

            ECDsaP256Signer signer;
            bool isEphemeral;

            if (keyPath is not null)
            {
                // Persistent mode: load from PEM file
                if (!File.Exists(keyPath))
                {
                    Console.Error.WriteLine($"Key file not found: {keyPath}");
                    return;
                }

                var pem = File.ReadAllText(keyPath);

                if (pem.Contains("ENCRYPTED", StringComparison.Ordinal))
                {
                    if (string.IsNullOrEmpty(passphrase))
                    {
                        Console.Error.WriteLine("Key is encrypted. Provide --passphrase.");
                        return;
                    }
                    signer = ECDsaP256Signer.FromEncryptedPem(pem, passphrase);
                }
                else
                {
                    signer = ECDsaP256Signer.FromPem(pem);
                }

                isEphemeral = false;
            }
            else
            {
                // Ephemeral mode: generate key in memory
                signer = ECDsaP256Signer.Generate();
                isEphemeral = true;
            }

            using (signer)
            {
                var fingerprint = KeyFingerprint.Compute(signer.PublicKey);
                var envelope = ArtifactSigner.Sign(artifact.FullName, signer, fingerprint, label);

                var outputPath = output ?? artifact.FullName + ".sig.json";
                var json = ArtifactSigner.Serialize(envelope);
                File.WriteAllText(outputPath, json);

                Console.WriteLine($"Signed: {artifact.Name}");
                Console.WriteLine($"Key: {fingerprint.ShortId}...");
                if (isEphemeral)
                    Console.WriteLine("Mode: ephemeral (key not persisted)");
                Console.WriteLine($"Signature: {outputPath}");
            }
        });

        return cmd;
    }
}
