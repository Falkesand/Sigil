namespace Sigil.Cli.Tests.Commands;

public class SignImageCommandTests
{
    [Fact]
    public async Task Missing_image_argument_shows_error()
    {
        var result = await CommandTestHelper.InvokeAsync("sign-image");

        // System.CommandLine shows an error for missing required argument
        Assert.NotEmpty(result.StdErr);
    }

    [Fact]
    public async Task Vault_and_key_mutually_exclusive()
    {
        var result = await CommandTestHelper.InvokeAsync(
            "sign-image", "localhost:5000/test:latest",
            "--key", "test.pem", "--vault", "hashicorp");

        Assert.Contains("Cannot use both --key and --vault", result.StdErr);
    }

    [Fact]
    public async Task Vault_key_without_vault_shows_error()
    {
        var result = await CommandTestHelper.InvokeAsync(
            "sign-image", "localhost:5000/test:latest",
            "--vault-key", "my-key");

        Assert.Contains("--vault is required", result.StdErr);
    }

    [Fact]
    public async Task Vault_without_vault_key_shows_error()
    {
        var result = await CommandTestHelper.InvokeAsync(
            "sign-image", "localhost:5000/test:latest",
            "--vault", "hashicorp");

        Assert.Contains("--vault-key is required", result.StdErr);
    }

    [Fact]
    public async Task Invalid_image_reference_shows_error()
    {
        var result = await CommandTestHelper.InvokeAsync(
            "sign-image", "   ");

        Assert.Contains("Invalid image reference", result.StdErr);
    }
}
