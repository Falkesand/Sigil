using Sigil.Discovery;

namespace Sigil.Core.Tests.Discovery;

public class GitBundleResolverTests : IDisposable
{
    private readonly string _tempDir;

    public GitBundleResolverTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-git-test-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempDir))
                Directory.Delete(_tempDir, true);
        }
        catch
        {
            // Best effort cleanup
        }
    }

    [Fact]
    public void ParseGitUrl_extracts_url_and_branch()
    {
        var (url, branch) = GitBundleResolver.ParseGitUrl("https://github.com/org/repo.git#v2");

        Assert.Equal("https://github.com/org/repo.git", url);
        Assert.Equal("v2", branch);
    }

    [Fact]
    public void ParseGitUrl_handles_no_fragment()
    {
        var (url, branch) = GitBundleResolver.ParseGitUrl("https://github.com/org/repo.git");

        Assert.Equal("https://github.com/org/repo.git", url);
        Assert.Null(branch);
    }

    [Fact]
    public void ValidateUrl_rejects_shell_metacharacters()
    {
        Assert.False(GitBundleResolver.IsUrlSafe("https://evil.com/repo;rm -rf /"));
        Assert.False(GitBundleResolver.IsUrlSafe("https://evil.com/repo|cat /etc/passwd"));
        Assert.False(GitBundleResolver.IsUrlSafe("https://evil.com/repo&echo pwned"));
        Assert.False(GitBundleResolver.IsUrlSafe("https://evil.com/repo`id`"));
        Assert.False(GitBundleResolver.IsUrlSafe("https://evil.com/repo$(id)"));
    }

    [Fact]
    public void ValidateUrl_accepts_safe_urls()
    {
        Assert.True(GitBundleResolver.IsUrlSafe("https://github.com/org/repo.git"));
        Assert.True(GitBundleResolver.IsUrlSafe("https://gitlab.com/org/project.git"));
        Assert.True(GitBundleResolver.IsUrlSafe("git@github.com:org/repo.git"));
    }

    [Fact]
    public void FindBundleFile_prefers_sigil_directory()
    {
        // Create both paths
        var sigilDir = Path.Combine(_tempDir, ".sigil");
        Directory.CreateDirectory(sigilDir);
        File.WriteAllText(Path.Combine(sigilDir, "trust.json"), """{"kind":"trust-bundle","from":".sigil"}""");
        File.WriteAllText(Path.Combine(_tempDir, "trust.json"), """{"kind":"trust-bundle","from":"root"}""");

        var result = GitBundleResolver.FindBundleFile(_tempDir);

        Assert.NotNull(result);
        Assert.Contains(".sigil", result, StringComparison.Ordinal);
    }

    [Fact]
    public void FindBundleFile_falls_back_to_root()
    {
        File.WriteAllText(Path.Combine(_tempDir, "trust.json"), """{"kind":"trust-bundle"}""");

        var result = GitBundleResolver.FindBundleFile(_tempDir);

        Assert.NotNull(result);
        Assert.EndsWith("trust.json", result);
    }

    [Fact]
    public void FindBundleFile_returns_null_when_not_found()
    {
        var result = GitBundleResolver.FindBundleFile(_tempDir);

        Assert.Null(result);
    }

    [Fact]
    public async Task ResolveAsync_rejects_unsafe_url()
    {
        var resolver = new GitBundleResolver();
        var result = await resolver.ResolveAsync("https://evil.com/repo;rm -rf /");

        Assert.False(result.IsSuccess);
        Assert.Equal(DiscoveryErrorKind.InvalidUri, result.ErrorKind);
    }
}
