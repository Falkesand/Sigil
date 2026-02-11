using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Sigil.Cli.Commands;

public sealed class ConsolePrompter : IConsolePrompter
{
    public static readonly ConsolePrompter Instance = new();

    public bool IsInteractive => !Console.IsInputRedirected;

    public string? ReadPassphrase(string prompt)
    {
        Console.Error.Write(prompt);
        var chars = new List<char>();
        try
        {
            while (true)
            {
                var key = Console.ReadKey(intercept: true);
                if (key.Key == ConsoleKey.Enter)
                {
                    Console.Error.WriteLine();
                    break;
                }

                if (key.Key == ConsoleKey.Backspace && chars.Count > 0)
                {
                    chars.RemoveAt(chars.Count - 1);
                    Console.Error.Write("\b \b");
                    continue;
                }

                if (key.KeyChar == '\0')
                    continue;

                chars.Add(key.KeyChar);
                Console.Error.Write('*');
            }

            if (chars.Count == 0)
                return null;

            char[] arr = chars.ToArray();
            try
            {
                return new string(arr);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(arr.AsSpan()));
            }
        }
        finally
        {
            for (int i = 0; i < chars.Count; i++)
                chars[i] = '\0';
        }
    }
}
