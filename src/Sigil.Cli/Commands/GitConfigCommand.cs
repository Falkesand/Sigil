using System.CommandLine;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Sigil.Cli.Vault;
using Sigil.Keys;

namespace Sigil.Cli.Commands;

public static class GitConfigCommand
{
    public static Command Create()
    {
        var keyOption = new Option<string?>("--key") { Description = "Path to a private key PEM file" };
        var globalOption = new Option<bool>("--global") { Description = "Set git config globally (also enables commit.gpgsign)" };
        var passphraseOption = new Option<string?>("--passphrase") { Description = "Passphrase if the signing key is encrypted" };
        var vaultOption = new Option<string?>("--vault") { Description = "Vault provider (hashicorp, azure, aws, gcp, pkcs11)" };
        var vaultKeyOption = new Option<string?>("--vault-key") { Description = "Key reference in the vault provider" };

        var cmd = new Command("config", "Configure git to use Sigil for commit/tag signing");
        cmd.Add(keyOption);
        cmd.Add(globalOption);
        cmd.Add(passphraseOption);
        cmd.Add(vaultOption);
        cmd.Add(vaultKeyOption);

        cmd.SetAction(async parseResult =>
        {
            var keyPath = parseResult.GetValue(keyOption);
            var isGlobal = parseResult.GetValue(globalOption);
            var passphrase = parseResult.GetValue(passphraseOption);
            var vaultName = parseResult.GetValue(vaultOption);
            var vaultKey = parseResult.GetValue(vaultKeyOption);

            // Validate mutual exclusivity
            if (keyPath is not null && vaultName is not null)
            {
                Console.Error.WriteLine("Cannot use both --key and --vault. Choose one signing method.");
                Environment.ExitCode = 1;
                return;
            }

            if (vaultName is not null && vaultKey is null)
            {
                Console.Error.WriteLine("--vault-key is required when using --vault.");
                Environment.ExitCode = 1;
                return;
            }

            if (vaultKey is not null && vaultName is null)
            {
                Console.Error.WriteLine("--vault is required when using --vault-key.");
                Environment.ExitCode = 1;
                return;
            }

            if (keyPath is null && vaultName is null)
            {
                Console.Error.WriteLine("--key or --vault/--vault-key is required.");
                Environment.ExitCode = 1;
                return;
            }

            string fingerprint;
            string wrapperPath;

            if (vaultName is not null)
            {
                // Vault path — resolve fingerprint from vault public key
                var createResult = VaultProviderFactory.Create(vaultName);
                if (!createResult.IsSuccess)
                {
                    Console.Error.WriteLine(createResult.ErrorMessage);
                    Environment.ExitCode = 1;
                    return;
                }

                await using var provider = createResult.Value;

                var pubKeyResult = await provider.GetPublicKeyAsync(vaultKey!);
                if (!pubKeyResult.IsSuccess)
                {
                    Console.Error.WriteLine(pubKeyResult.ErrorMessage);
                    Environment.ExitCode = 1;
                    return;
                }

                fingerprint = KeyFingerprint.Compute(pubKeyResult.Value).Value;

                // Generate vault wrapper script
                var sigilPath = FindSigilExecutable();
                wrapperPath = GenerateVaultWrapper(sigilPath, vaultName, vaultKey!);
            }
            else
            {
                // PEM path
                var fullKeyPath = Path.GetFullPath(keyPath!);

                var loadResult = PemSignerLoader.Load(fullKeyPath, passphrase, null);
                if (!loadResult.IsSuccess)
                {
                    Console.Error.WriteLine(loadResult.ErrorMessage);
                    Environment.ExitCode = 1;
                    return;
                }

                using (var signer = loadResult.Value)
                {
                    fingerprint = KeyFingerprint.Compute(signer.PublicKey).Value;
                }

                // Generate PEM wrapper script
                var sigilPath = FindSigilExecutable();
                wrapperPath = GenerateWrapper(sigilPath, fullKeyPath, passphrase);

                if (passphrase is not null)
                {
                    Console.Error.WriteLine("Warning: Passphrase is stored in plaintext in the wrapper script.");
                    Console.Error.WriteLine($"  File: {wrapperPath}");
                    Console.Error.WriteLine("  Consider using SIGIL_PASSPHRASE environment variable instead.");
                }
            }

            // Configure git
            var scope = isGlobal ? "--global" : "--local";
            RunGitConfig(scope, "gpg.format", "x509");
            RunGitConfig(scope, "gpg.x509.program", wrapperPath);
            RunGitConfig(scope, "user.signingkey", fingerprint);

            if (isGlobal)
            {
                RunGitConfig(scope, "commit.gpgsign", "true");
            }

            Console.WriteLine($"Git signing configured with Sigil.");
            Console.WriteLine($"  Key: {fingerprint[..20]}...");
            Console.WriteLine($"  Wrapper: {wrapperPath}");
            Console.WriteLine($"  Scope: {(isGlobal ? "global" : "local")}");

            if (!isGlobal)
            {
                Console.WriteLine("  Tip: Use -S flag to sign commits, or run with --global to sign all commits.");
            }
        });

        return cmd;
    }

    private static string FindSigilExecutable()
    {
        var currentProcess = Environment.ProcessPath;
        if (currentProcess is not null && File.Exists(currentProcess))
            return currentProcess;

        // Fallback: assume sigil is on PATH
        return "sigil";
    }

    private static string GenerateWrapper(string sigilPath, string keyPath, string? passphrase)
    {
        var sigilDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".sigil");
        Directory.CreateDirectory(sigilDir);

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            var wrapperPath = Path.Combine(sigilDir, "git-sign.bat");
            var passphraseArg = passphrase is not null
                ? $" --passphrase \"{EscapeBatchPassphrase(passphrase)}\""
                : "";
            var content = $"@\"{sigilPath}\" git-sign --key \"{keyPath}\"{passphraseArg} %*\r\n";
            File.WriteAllText(wrapperPath, content);
            return wrapperPath;
        }
        else
        {
            var wrapperPath = Path.Combine(sigilDir, "git-sign.sh");
            var passphraseArg = passphrase is not null
                ? $" --passphrase '{EscapeShellPassphrase(passphrase)}'"
                : "";
            var content = $"#!/bin/sh\nexec \"{sigilPath}\" git-sign --key \"{keyPath}\"{passphraseArg} \"$@\"\n";
            File.WriteAllText(wrapperPath, content);

            MakeExecutable(wrapperPath);

            return wrapperPath;
        }
    }

    private static string GenerateVaultWrapper(string sigilPath, string vaultName, string vaultKey)
    {
        var sigilDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".sigil");
        Directory.CreateDirectory(sigilDir);

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            var wrapperPath = Path.Combine(sigilDir, "git-sign.bat");
            var escapedKey = EscapeBatchPassphrase(vaultKey);
            var content = $"@\"{sigilPath}\" git-sign --vault \"{vaultName}\" --vault-key \"{escapedKey}\" %*\r\n";
            File.WriteAllText(wrapperPath, content);
            return wrapperPath;
        }
        else
        {
            var wrapperPath = Path.Combine(sigilDir, "git-sign.sh");
            var escapedKey = EscapeShellPassphrase(vaultKey);
            var content = $"#!/bin/sh\nexec \"{sigilPath}\" git-sign --vault \"{vaultName}\" --vault-key '{escapedKey}' \"$@\"\n";
            File.WriteAllText(wrapperPath, content);

            MakeExecutable(wrapperPath);

            return wrapperPath;
        }
    }

    private static void MakeExecutable(string path)
    {
        try
        {
            var chmodPsi = new ProcessStartInfo("chmod")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            chmodPsi.ArgumentList.Add("+x");
            chmodPsi.ArgumentList.Add(path);
            using var chmod = Process.Start(chmodPsi);
            chmod?.WaitForExit(5000);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // chmod may not be available on all systems (e.g., Windows)
        }
    }

    private static void RunGitConfig(string scope, string key, string value)
    {
        try
        {
            var psi = new ProcessStartInfo("git")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            psi.ArgumentList.Add("config");
            psi.ArgumentList.Add(scope);
            psi.ArgumentList.Add(key);
            psi.ArgumentList.Add(value);

            using var process = Process.Start(psi);
            process?.WaitForExit(5000);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            Console.Error.WriteLine($"Warning: Failed to set git config {key}: {ex.Message}");
        }
    }

    /// <summary>
    /// Escapes a passphrase for safe embedding in a Windows batch file.
    /// Prevents command injection via &amp;, |, &gt;, &lt;, ^, and " characters.
    /// </summary>
    private static string EscapeBatchPassphrase(string passphrase)
    {
        // In batch files, ^ is the escape character for special chars.
        // Must escape ^ first (before other chars get ^ prefixed).
        // Also escape " since the passphrase is inside double quotes.
        return passphrase
            .Replace("^", "^^")
            .Replace("&", "^&")
            .Replace("|", "^|")
            .Replace("<", "^<")
            .Replace(">", "^>")
            .Replace("\"", "^\"");
    }

    /// <summary>
    /// Escapes a passphrase for safe embedding in a POSIX shell single-quoted string.
    /// The only character that needs escaping in single quotes is the single quote itself.
    /// </summary>
    private static string EscapeShellPassphrase(string passphrase)
    {
        // In single-quoted strings, ' cannot be escaped. The standard technique
        // is to end the single-quoted string, add an escaped single quote, and
        // start a new single-quoted string: 'foo'\''bar' → foo'bar
        return passphrase.Replace("'", @"'\''");
    }
}
