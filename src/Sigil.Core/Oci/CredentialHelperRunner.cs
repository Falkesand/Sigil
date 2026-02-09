using System.Buffers;
using System.Diagnostics;
using System.Text.Json;

namespace Sigil.Oci;

/// <summary>
/// Runs Docker credential helpers (docker-credential-*) to obtain registry credentials.
/// </summary>
public static class CredentialHelperRunner
{
    private static readonly SearchValues<char> UnsafeChars =
        SearchValues.Create(";|&`$(){}< >'\"\n\r\\");

    private static readonly TimeSpan HelperTimeout = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Runs a Docker credential helper to obtain registry credentials.
    /// Environment variable overrides are handled by the CLI layer (RegistryCredentialResolver).
    /// </summary>
    public static OciResult<RegistryCredentials> Get(string helperName, string registry)
    {
        if (!IsNameSafe(helperName))
        {
            return OciResult<RegistryCredentials>.Fail(
                OciErrorKind.AuthenticationFailed,
                $"Credential helper name contains unsafe characters: '{helperName}'.");
        }

        return RunHelper(helperName, registry);
    }

    internal static bool IsNameSafe(string name) =>
        !string.IsNullOrEmpty(name) && name.AsSpan().IndexOfAny(UnsafeChars) < 0;

    private static OciResult<RegistryCredentials> RunHelper(string helperName, string registry)
    {
        var program = $"docker-credential-{helperName}";

        try
        {
            using var process = new Process();
            process.StartInfo = new ProcessStartInfo
            {
                FileName = program,
                Arguments = "get",
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            process.Start();

            process.StandardInput.Write(registry);
            process.StandardInput.Close();

            if (!process.WaitForExit((int)HelperTimeout.TotalMilliseconds))
            {
                if (!process.HasExited)
                {
                    try { process.Kill(); }
                    catch (InvalidOperationException) { /* race: exited between check and kill */ }
                }
                return OciResult<RegistryCredentials>.Fail(
                    OciErrorKind.Timeout,
                    $"Credential helper '{program}' timed out.");
            }

            if (process.ExitCode != 0)
            {
                return OciResult<RegistryCredentials>.Fail(
                    OciErrorKind.AuthenticationFailed,
                    $"Credential helper '{program}' exited with code {process.ExitCode}.");
            }

            var output = process.StandardOutput.ReadToEnd();
            return ParseHelperOutput(output);
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return OciResult<RegistryCredentials>.Fail(
                OciErrorKind.AuthenticationFailed,
                $"Credential helper '{program}' not found.");
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return OciResult<RegistryCredentials>.Fail(
                OciErrorKind.AuthenticationFailed,
                $"Credential helper error: {ex.Message}");
        }
    }

    internal static OciResult<RegistryCredentials> ParseHelperOutput(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            var username = root.TryGetProperty("Username", out var u) ? u.GetString() : null;
            var secret = root.TryGetProperty("Secret", out var s) ? s.GetString() : null;

            return OciResult<RegistryCredentials>.Ok(new RegistryCredentials
            {
                Username = username,
                Password = secret
            });
        }
        catch (JsonException ex)
        {
            return OciResult<RegistryCredentials>.Fail(
                OciErrorKind.AuthenticationFailed,
                $"Failed to parse credential helper output: {ex.Message}");
        }
    }
}
