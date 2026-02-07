using System.CommandLine;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
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
        var algorithmOption = new Option<string?>("--algorithm") { Description = "Signing algorithm for ephemeral mode (ecdsa-p256, ecdsa-p384, rsa-pss-sha256)" };

        var cmd = new Command("sign", "Sign an artifact and produce a detached signature envelope");
        cmd.Add(artifactArg);
        cmd.Add(keyOption);
        cmd.Add(outputOption);
        cmd.Add(labelOption);
        cmd.Add(passphraseOption);
        cmd.Add(algorithmOption);

        cmd.SetAction(parseResult =>
        {
            var artifact = parseResult.GetValue(artifactArg)!;
            var keyPath = parseResult.GetValue(keyOption);
            var output = parseResult.GetValue(outputOption);
            var label = parseResult.GetValue(labelOption);
            var passphrase = parseResult.GetValue(passphraseOption);
            var algorithmName = parseResult.GetValue(algorithmOption) ?? "ecdsa-p256";

            if (!artifact.Exists)
            {
                Console.Error.WriteLine($"Artifact not found: {artifact.FullName}");
                return;
            }

            ISigner signer;
            bool isEphemeral;

            // Convert passphrase to char[] so we can zero it after use
            char[]? passphraseChars = passphrase?.ToCharArray();

            try
            {
                if (keyPath is not null)
                {
                    // Persistent mode: load from PEM file with auto-detection
                    if (!File.Exists(keyPath))
                    {
                        Console.Error.WriteLine($"Key file not found: {keyPath}");
                        return;
                    }

                    // Read PEM as bytes → chars to avoid interned string copies
                    byte[] pemBytes = File.ReadAllBytes(keyPath);
                    char[] pemChars = Encoding.UTF8.GetChars(pemBytes);
                    try
                    {
                        bool isEncrypted = pemChars.AsSpan().IndexOf("ENCRYPTED".AsSpan()) >= 0;
                        if (isEncrypted)
                        {
                            if (passphraseChars is null || passphraseChars.Length == 0)
                            {
                                Console.Error.WriteLine("Key is encrypted. Provide --passphrase.");
                                return;
                            }
                            signer = SignerFactory.CreateFromPem(pemChars, passphraseChars);
                        }
                        else
                        {
                            signer = SignerFactory.CreateFromPem(pemChars);
                        }
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(pemBytes);
                        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(pemChars.AsSpan()));
                    }

                    isEphemeral = false;
                }
                else
                {
                    // Ephemeral mode: generate key in memory
                    SigningAlgorithm algorithm;
                    try
                    {
                        algorithm = SigningAlgorithmExtensions.ParseAlgorithm(algorithmName);
                    }
                    catch (ArgumentException)
                    {
                        Console.Error.WriteLine($"Unknown algorithm: {algorithmName}");
                        Console.Error.WriteLine("Supported: ecdsa-p256, ecdsa-p384, rsa-pss-sha256");
                        return;
                    }

                    signer = SignerFactory.Generate(algorithm);
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
                    Console.WriteLine($"Algorithm: {signer.Algorithm.ToCanonicalName()}");
                    Console.WriteLine($"Key: {fingerprint.ShortId}...");
                    if (isEphemeral)
                        Console.WriteLine("Mode: ephemeral (key not persisted)");
                    Console.WriteLine($"Signature: {outputPath}");
                }
            }
            finally
            {
                if (passphraseChars is not null)
                    CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(passphraseChars.AsSpan()));
            }
        });

        return cmd;
    }
}
