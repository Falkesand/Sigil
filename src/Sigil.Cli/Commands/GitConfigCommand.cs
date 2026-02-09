using System.CommandLine;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Sigil.Keys;

namespace Sigil.Cli.Commands;

public static class GitConfigCommand
{
    public static Command Create()
    {
        var keyOption = new Option<string>("--key") { Description = "Path to a private key PEM file" };
        keyOption.Required = true;
        var globalOption = new Option<bool>("--global") { Description = "Set git config globally (also enables commit.gpgsign)" };
        var passphraseOption = new Option<string?>("--passphrase") { Description = "Passphrase if the signing key is encrypted" };

        var cmd = new Command("config", "Configure git to use Sigil for commit/tag signing");
        cmd.Add(keyOption);
        cmd.Add(globalOption);
        cmd.Add(passphraseOption);

        cmd.SetAction(parseResult =>
        {
            var keyPath = parseResult.GetValue(keyOption)!;
            var isGlobal = parseResult.GetValue(globalOption);
            var passphrase = parseResult.GetValue(passphraseOption);

            var fullKeyPath = Path.GetFullPath(keyPath);

            // Validate key exists and can be loaded
            var loadResult = PemSignerLoader.Load(fullKeyPath, passphrase, null);
            if (!loadResult.IsSuccess)
            {
                Console.Error.WriteLine(loadResult.ErrorMessage);
                Environment.ExitCode = 1;
                return;
            }

            string fingerprint;
            using (var signer = loadResult.Value)
            {
                fingerprint = KeyFingerprint.Compute(signer.PublicKey).Value;
            }

            // Find sigil executable path
            var sigilPath = FindSigilExecutable();

            // Generate wrapper script
            var wrapperPath = GenerateWrapper(sigilPath, fullKeyPath, passphrase);

            if (passphrase is not null)
            {
                Console.Error.WriteLine("Warning: Passphrase is stored in plaintext in the wrapper script.");
                Console.Error.WriteLine($"  File: {wrapperPath}");
                Console.Error.WriteLine("  Consider using an unencrypted key or SIGIL_PASSPHRASE environment variable.");
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

            // Make executable
            try
            {
                var chmodPsi = new ProcessStartInfo("chmod")
                {
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                chmodPsi.ArgumentList.Add("+x");
                chmodPsi.ArgumentList.Add(wrapperPath);
                using var chmod = Process.Start(chmodPsi);
                chmod?.WaitForExit(5000);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                // chmod may not be available on all systems (e.g., Windows)
            }

            return wrapperPath;
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
