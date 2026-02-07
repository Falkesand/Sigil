using System.CommandLine;
using Sigil.Keys;
using Sigil.Signing;

namespace Sigil.Cli.Commands;

public static class SignCommand
{
    public static Command Create()
    {
        var artifactArg = new Argument<FileInfo>("artifact") { Description = "Path to the artifact to sign" };
        var keyOption = new Option<string>("--key") { Description = "Key fingerprint (or prefix) to sign with", Required = true };
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
            var keyRef = parseResult.GetValue(keyOption)!;
            var output = parseResult.GetValue(outputOption);
            var label = parseResult.GetValue(labelOption);
            var passphrase = parseResult.GetValue(passphraseOption);

            if (!artifact.Exists)
            {
                Console.Error.WriteLine($"Artifact not found: {artifact.FullName}");
                return;
            }

            var store = KeyStore.Default();
            var fingerprint = KeysCommand.ResolveFingerprint(store, keyRef);

            using var signer = store.LoadSigner(fingerprint, passphrase);
            var envelope = ArtifactSigner.Sign(artifact.FullName, signer, fingerprint, label);

            var outputPath = output ?? artifact.FullName + ".sig.json";
            var json = ArtifactSigner.Serialize(envelope);
            File.WriteAllText(outputPath, json);

            Console.WriteLine($"Signed: {artifact.Name}");
            Console.WriteLine($"Key: {fingerprint.ShortId}...");
            Console.WriteLine($"Signature: {outputPath}");
        });

        return cmd;
    }
}
