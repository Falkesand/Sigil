using System.Buffers;
using System.Diagnostics;

namespace Sigil.Discovery;

/// <summary>
/// Resolves trust bundles from git repositories.
/// Performs a shallow clone and looks for .sigil/trust.json or trust.json.
/// </summary>
public sealed class GitBundleResolver : IDiscoveryResolver
{
    private static readonly TimeSpan CloneTimeout = TimeSpan.FromSeconds(60);

    // Characters that could enable shell injection
    private static readonly SearchValues<char> UnsafeChars =
        SearchValues.Create(";|&`$(){}< >'\"\n\r");

    public async Task<DiscoveryResult<string>> ResolveAsync(
        string identifier,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(identifier);

        if (!IsUrlSafe(identifier))
        {
            return DiscoveryResult<string>.Fail(DiscoveryErrorKind.InvalidUri,
                "Git URL contains unsafe characters.");
        }

        var (url, branch) = ParseGitUrl(identifier);

        var tempDir = Path.Combine(Path.GetTempPath(), "sigil-git-" + Guid.NewGuid().ToString("N")[..8]);

        try
        {
            var cloneResult = await CloneAsync(url, branch, tempDir, cancellationToken).ConfigureAwait(false);
            if (!cloneResult.IsSuccess)
                return cloneResult;

            var bundlePath = FindBundleFile(tempDir);
            if (bundlePath is null)
            {
                return DiscoveryResult<string>.Fail(DiscoveryErrorKind.NotFound,
                    "No trust bundle file found in repository. Expected .sigil/trust.json or trust.json.");
            }

            var content = await File.ReadAllTextAsync(bundlePath, cancellationToken).ConfigureAwait(false);
            return DiscoveryResult<string>.Ok(content);
        }
        finally
        {
            CleanupDirectory(tempDir);
        }
    }

    /// <summary>
    /// Parses a git URL, extracting optional branch/tag from URL fragment.
    /// </summary>
    public static (string Url, string? Branch) ParseGitUrl(string identifier)
    {
        var hashIdx = identifier.LastIndexOf('#');
        if (hashIdx > 0 && hashIdx < identifier.Length - 1)
        {
            return (identifier[..hashIdx], identifier[(hashIdx + 1)..]);
        }

        return (identifier, null);
    }

    /// <summary>
    /// Validates that a URL doesn't contain shell injection characters.
    /// </summary>
    public static bool IsUrlSafe(string url)
    {
        return url.AsSpan().IndexOfAny(UnsafeChars) < 0;
    }

    /// <summary>
    /// Finds the trust bundle file in a cloned repository.
    /// Priority: .sigil/trust.json > trust.json
    /// </summary>
    public static string? FindBundleFile(string repoDir)
    {
        var sigilPath = Path.Combine(repoDir, ".sigil", "trust.json");
        if (File.Exists(sigilPath))
            return sigilPath;

        var rootPath = Path.Combine(repoDir, "trust.json");
        if (File.Exists(rootPath))
            return rootPath;

        return null;
    }

    private static async Task<DiscoveryResult<string>> CloneAsync(
        string url,
        string? branch,
        string targetDir,
        CancellationToken cancellationToken)
    {
        var args = branch is not null
            ? $"clone --depth 1 --branch {branch} -- {url} {targetDir}"
            : $"clone --depth 1 -- {url} {targetDir}";

        try
        {
            using var process = new Process();
            process.StartInfo = new ProcessStartInfo
            {
                FileName = "git",
                Arguments = args,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            process.Start();

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(CloneTimeout);

            try
            {
                await process.WaitForExitAsync(cts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                try { process.Kill(entireProcessTree: true); }
                catch { /* best effort */ }

                return DiscoveryResult<string>.Fail(DiscoveryErrorKind.Timeout,
                    $"Git clone timed out after {CloneTimeout.TotalSeconds}s.");
            }

            if (process.ExitCode != 0)
            {
                var stderr = await process.StandardError.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
                return DiscoveryResult<string>.Fail(DiscoveryErrorKind.GitError,
                    $"Git clone failed (exit code {process.ExitCode}): {stderr.Trim()}");
            }

            // Success — caller will read the bundle file
            return DiscoveryResult<string>.Ok(string.Empty);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return DiscoveryResult<string>.Fail(DiscoveryErrorKind.GitError,
                $"Failed to run git: {ex.Message}");
        }
    }

    private static void CleanupDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                // Git clone creates read-only files — remove that attribute
                foreach (var file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
                {
                    File.SetAttributes(file, FileAttributes.Normal);
                }
                Directory.Delete(path, true);
            }
        }
        catch
        {
            // Best effort cleanup
        }
    }
}
