namespace Sigil.Cli.Tests.Commands;

public class DiscoverCommandTests
{
    [Fact]
    public async Task Discover_wellknown_missing_domain_shows_help()
    {
        // Invoking without required argument should show usage/error
        var result = await CommandTestHelper.InvokeAsync("discover", "well-known");

        // System.CommandLine outputs help or error when required arg missing
        Assert.True(result.ExitCode != 0 || result.StdErr.Length > 0 || result.StdOut.Contains("domain"),
            "Should indicate missing required argument");
    }

    [Fact]
    public async Task Discover_dns_missing_domain_shows_help()
    {
        var result = await CommandTestHelper.InvokeAsync("discover", "dns");

        Assert.True(result.ExitCode != 0 || result.StdErr.Length > 0 || result.StdOut.Contains("domain"),
            "Should indicate missing required argument");
    }

    [Fact]
    public async Task Discover_git_missing_url_shows_help()
    {
        var result = await CommandTestHelper.InvokeAsync("discover", "git");

        Assert.True(result.ExitCode != 0 || result.StdErr.Length > 0 || result.StdOut.Contains("url"),
            "Should indicate missing required argument");
    }

    [Fact]
    public async Task Discover_git_unsafe_url_shows_error()
    {
        var result = await CommandTestHelper.InvokeAsync("discover", "git", "https://evil.com;rm -rf /");

        Assert.Contains("unsafe", result.StdErr, StringComparison.OrdinalIgnoreCase);
    }
}
