using System.CommandLine;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Sigil.Keys;
using Sigil.Pe;
using Sigil.Signing;
using Sigil.Timestamping;

namespace Sigil.Cli.Commands;

public static class SignPeCommand
{
    private const long MaxPeFileSize = 500 * 1024 * 1024; // 500 MB
    private static readonly string[] PfxExtensions = [".pfx", ".p12"];

    public static Command Create()
    {
        var peFileArg = new Argument<string>("pe-file") { Description = "Path to the PE binary (.exe, .dll)" };
        var keyOption = new Option<string?>("--key") { Description = "Path to a PFX/P12 certificate file" };
        var certStoreOption = new Option<string?>("--cert-store") { Description = "Certificate thumbprint for Windows Certificate Store" };
        var storeLocationOption = new Option<string?>("--store-location") { Description = "Store location: CurrentUser (default) or LocalMachine" };
        var outputOption = new Option<string?>("--output") { Description = "Output path for signed PE (default: overwrite in-place)" };
        var envelopeOption = new Option<string?>("--envelope") { Description = "Output path for .sig.json envelope" };
        var labelOption = new Option<string?>("--label") { Description = "Label for this signature" };
        var passphraseOption = new Option<string?>("--passphrase") { Description = "Passphrase for the PFX file" };
        var passphraseFileOption = new Option<string?>("--passphrase-file") { Description = "Path to file containing the passphrase" };
        var timestampOption = new Option<string?>("--timestamp") { Description = "TSA URL for RFC 3161 timestamping" };

        var cmd = new Command("sign-pe", "Sign a PE binary with Authenticode + Sigil envelope");
        cmd.Add(peFileArg);
        cmd.Add(keyOption);
        cmd.Add(certStoreOption);
        cmd.Add(storeLocationOption);
        cmd.Add(outputOption);
        cmd.Add(envelopeOption);
        cmd.Add(labelOption);
        cmd.Add(passphraseOption);
        cmd.Add(passphraseFileOption);
        cmd.Add(timestampOption);

        cmd.SetAction(async parseResult =>
        {
            var peFilePath = parseResult.GetValue(peFileArg)!;
            var keyPath = parseResult.GetValue(keyOption);
            var certStoreThumbprint = parseResult.GetValue(certStoreOption);
            var storeLocationName = parseResult.GetValue(storeLocationOption);
            var outputPath = parseResult.GetValue(outputOption);
            var envelopePath = parseResult.GetValue(envelopeOption);
            var label = parseResult.GetValue(labelOption);
            var passphrase = parseResult.GetValue(passphraseOption);
            var passphraseFile = parseResult.GetValue(passphraseFileOption);
            var tsaUrl = parseResult.GetValue(timestampOption);

            if (!File.Exists(peFilePath))
            {
                Console.Error.WriteLine($"PE file not found: {peFilePath}");
                Environment.ExitCode = 1;
                return;
            }

            // Validate: must provide exactly one of --key or --cert-store
            if (keyPath is null && certStoreThumbprint is null)
            {
                Console.Error.WriteLine("Authenticode requires a certificate. Provide --key (PFX) or --cert-store.");
                Environment.ExitCode = 1;
                return;
            }

            if (keyPath is not null && certStoreThumbprint is not null)
            {
                Console.Error.WriteLine("Cannot use both --key and --cert-store. Choose one signing method.");
                Environment.ExitCode = 1;
                return;
            }

            if (storeLocationName is not null && certStoreThumbprint is null)
            {
                Console.Error.WriteLine("--store-location requires --cert-store.");
                Environment.ExitCode = 1;
                return;
            }

            // Reject PEM keys — Authenticode requires certificates
            if (keyPath is not null)
            {
                var ext = Path.GetExtension(keyPath);
                if (!PfxExtensions.Any(e => string.Equals(e, ext, StringComparison.OrdinalIgnoreCase)))
                {
                    Console.Error.WriteLine("Authenticode requires a PFX/P12 certificate file. PEM keys are not supported for PE signing.");
                    Environment.ExitCode = 1;
                    return;
                }
            }

            outputPath ??= peFilePath;
            envelopePath ??= peFilePath + ".sig.json";

            var fileInfo = new FileInfo(peFilePath);
            if (fileInfo.Length > MaxPeFileSize)
            {
                Console.Error.WriteLine($"PE file too large: {fileInfo.Length:N0} bytes (max {MaxPeFileSize:N0}).");
                Environment.ExitCode = 1;
                return;
            }

            var peBytes = File.ReadAllBytes(peFilePath);

            // Load certificate
            X509Certificate2? cert = null;
            try
            {
                if (keyPath is not null)
                {
                    var resolvedPassphrase = PassphraseResolver.Resolve(passphrase, passphraseFile, keyPath: keyPath);
                    var loadResult = CertificateLoader.LoadFromPfx(keyPath, resolvedPassphrase);
                    if (!loadResult.IsSuccess)
                    {
                        Console.Error.WriteLine(loadResult.ErrorMessage);
                        Environment.ExitCode = 1;
                        return;
                    }
                    cert = loadResult.Value;
                }
                else if (certStoreThumbprint is not null)
                {
                    if (!OperatingSystem.IsWindows())
                    {
                        Console.Error.WriteLine("--cert-store is only supported on Windows.");
                        Environment.ExitCode = 1;
                        return;
                    }
                    var storeLocation = storeLocationName is not null
                        ? Enum.Parse<StoreLocation>(storeLocationName, ignoreCase: true)
                        : StoreLocation.CurrentUser;
                    var loadResult = CertificateLoader.LoadFromCertStore(certStoreThumbprint, storeLocation);
                    if (!loadResult.IsSuccess)
                    {
                        Console.Error.WriteLine(loadResult.ErrorMessage);
                        Environment.ExitCode = 1;
                        return;
                    }
                    cert = loadResult.Value;
                }

                // Sign the PE
                var signResult = AuthenticodeSigner.Sign(peBytes, cert!, label, Path.GetFileName(peFilePath));
                if (!signResult.IsSuccess)
                {
                    Console.Error.WriteLine($"Signing failed: {signResult.ErrorMessage}");
                    Environment.ExitCode = 1;
                    return;
                }

                var result = signResult.Value;

                // Apply timestamp if requested
                if (tsaUrl is not null)
                {
                    result = await ApplyTimestampsAsync(result, tsaUrl);
                }

                // Write signed PE
                File.WriteAllBytes(outputPath, result.SignedPeBytes);

                // Write .sig.json envelope
                var json = ArtifactSigner.Serialize(result.Envelope);
                File.WriteAllText(envelopePath, json);

                Console.WriteLine($"PE signed: {Path.GetFileName(peFilePath)}");
                Console.WriteLine($"Subject: {cert!.Subject}");
                Console.WriteLine($"Thumbprint: {cert.Thumbprint}");
                Console.WriteLine($"Output: {outputPath}");
                Console.WriteLine($"Envelope: {envelopePath}");
            }
            finally
            {
                cert?.Dispose();
            }
        });

        return cmd;
    }

    private static async Task<AuthenticodeSignResult> ApplyTimestampsAsync(
        AuthenticodeSignResult result, string tsaUrl)
    {
        if (!Uri.TryCreate(tsaUrl, UriKind.Absolute, out var tsaUri))
        {
            Console.Error.WriteLine($"Warning: Invalid TSA URL: {tsaUrl}. PE signed without timestamp.");
            return result;
        }

        // Timestamp the .sig.json envelope entry
        var lastEntry = result.Envelope.Signatures[^1];
        var envTsResult = await TimestampApplier.ApplyAsync(lastEntry, tsaUri).ConfigureAwait(false);
        if (envTsResult.IsSuccess)
        {
            result.Envelope.Signatures[^1] = envTsResult.Value;
            Console.WriteLine("Timestamp applied to Sigil envelope.");
        }
        else
        {
            Console.Error.WriteLine($"Warning: Envelope timestamping failed ({envTsResult.ErrorMessage}).");
        }

        // Timestamp the Authenticode signature
        var peFile = PeFile.Parse(result.SignedPeBytes);
        if (peFile.IsSuccess && peFile.Value.CertTableSize > 0)
        {
            int certOffset = (int)peFile.Value.CertTableFileOffset;
            uint dwLength = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(
                result.SignedPeBytes.AsSpan(certOffset));
            int pkcs7Length = (int)dwLength - 8;
            var pkcs7Bytes = result.SignedPeBytes.AsSpan(certOffset + 8, pkcs7Length).ToArray();

            var authTsResult = await AuthenticodeTimestamper.ApplyTimestampAsync(
                pkcs7Bytes, tsaUri).ConfigureAwait(false);

            if (authTsResult.IsSuccess)
            {
                var replaceResult = AuthenticodeSigner.ReplacePkcs7(
                    result.SignedPeBytes, authTsResult.Value);
                if (replaceResult.IsSuccess)
                {
                    result = new AuthenticodeSignResult
                    {
                        SignedPeBytes = replaceResult.Value,
                        Envelope = result.Envelope
                    };
                    Console.WriteLine("Timestamp applied to Authenticode signature.");
                }
            }
            else
            {
                Console.Error.WriteLine($"Warning: Authenticode timestamping failed ({authTsResult.ErrorMessage}).");
            }
        }

        return result;
    }
}
