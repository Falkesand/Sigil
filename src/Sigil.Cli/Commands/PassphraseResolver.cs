using System.Security.Cryptography;
using System.Text;

namespace Sigil.Cli.Commands;

public static class PassphraseResolver
{
    public const string EnvVarName = "SIGIL_PASSPHRASE";
    public const string EnvVarFileName = "SIGIL_PASSPHRASE_FILE";

    public static string? Resolve(
        string? cliPassphrase,
        string? cliPassphraseFile,
        IConsolePrompter? prompter = null,
        bool allowInteractivePrompt = true,
        string promptMessage = "Enter passphrase: ")
    {
        // 1. --passphrase arg
        if (cliPassphrase is not null)
            return cliPassphrase;

        // 2. --passphrase-file path
        if (cliPassphraseFile is not null)
            return ReadPassphraseFile(cliPassphraseFile);

        // 3. SIGIL_PASSPHRASE env var
        var envPassphrase = Environment.GetEnvironmentVariable(EnvVarName);
        if (!string.IsNullOrEmpty(envPassphrase))
            return envPassphrase;

        // 4. SIGIL_PASSPHRASE_FILE env var
        var envFilePath = Environment.GetEnvironmentVariable(EnvVarFileName);
        if (!string.IsNullOrEmpty(envFilePath))
            return ReadPassphraseFile(envFilePath);

        // 5. Interactive prompt (if allowed and TTY)
        if (allowInteractivePrompt)
        {
            prompter ??= ConsolePrompter.Instance;
            if (prompter.IsInteractive)
                return prompter.ReadPassphrase(promptMessage);
        }

        return null;
    }

    private static string ReadPassphraseFile(string filePath)
    {
        byte[] fileBytes = File.ReadAllBytes(filePath);
        try
        {
            int start = 0;
            int length = fileBytes.Length;

            // Skip UTF-8 BOM if present (common on Windows)
            if (length >= 3 && fileBytes[0] == 0xEF && fileBytes[1] == 0xBB && fileBytes[2] == 0xBF)
                start = 3;

            while (length > start && (fileBytes[length - 1] == '\n' || fileBytes[length - 1] == '\r'))
                length--;

            return Encoding.UTF8.GetString(fileBytes, start, length - start);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fileBytes);
        }
    }
}
