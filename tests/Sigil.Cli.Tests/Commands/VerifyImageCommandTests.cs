namespace Sigil.Cli.Tests.Commands;

public class VerifyImageCommandTests
{
    [Fact]
    public async Task Missing_image_argument_shows_error()
    {
        var result = await CommandTestHelper.InvokeAsync("verify-image");

        // System.CommandLine shows an error for missing required argument
        Assert.NotEmpty(result.StdErr);
    }

    [Fact]
    public async Task Policy_and_trust_bundle_mutually_exclusive()
    {
        var result = await CommandTestHelper.InvokeAsync(
            "verify-image", "localhost:5000/test:latest",
            "--policy", "policy.json", "--trust-bundle", "bundle.json");

        Assert.Contains("--policy is mutually exclusive", result.StdErr);
    }

    [Fact]
    public async Task Policy_and_discover_mutually_exclusive()
    {
        var result = await CommandTestHelper.InvokeAsync(
            "verify-image", "localhost:5000/test:latest",
            "--policy", "policy.json", "--discover", "example.com");

        Assert.Contains("--policy is mutually exclusive", result.StdErr);
    }

    [Fact]
    public async Task Trust_bundle_and_discover_mutually_exclusive()
    {
        var result = await CommandTestHelper.InvokeAsync(
            "verify-image", "localhost:5000/test:latest",
            "--trust-bundle", "bundle.json", "--discover", "example.com");

        Assert.Contains("mutually exclusive", result.StdErr);
    }

    [Fact]
    public async Task Invalid_image_reference_shows_error()
    {
        var result = await CommandTestHelper.InvokeAsync(
            "verify-image", "   ");

        Assert.Contains("Invalid image reference", result.StdErr);
    }
}
