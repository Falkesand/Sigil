using Sigil.Vault;
using Sigil.Vault.Aws;

namespace Sigil.Vault.Aws.Tests;

[Collection("AwsEnvironment")]
public class AwsAuthFactoryTests : IDisposable
{
    private readonly string? _originalValue;

    public AwsAuthFactoryTests()
    {
        _originalValue = Environment.GetEnvironmentVariable("AWS_REGION");
    }

    public void Dispose()
    {
        Environment.SetEnvironmentVariable("AWS_REGION", _originalValue);
    }

    [Fact]
    public void CreateClient_MissingEnvVar_ReturnsConfigurationError()
    {
        Environment.SetEnvironmentVariable("AWS_REGION", null);

        var result = AwsAuthFactory.CreateClient();

        Assert.False(result.IsSuccess);
        Assert.Equal(VaultErrorKind.ConfigurationError, result.ErrorKind);
        Assert.Contains("AWS_REGION", result.ErrorMessage);
    }

    [Fact]
    public void CreateClient_EmptyEnvVar_ReturnsConfigurationError()
    {
        Environment.SetEnvironmentVariable("AWS_REGION", "");

        var result = AwsAuthFactory.CreateClient();

        Assert.False(result.IsSuccess);
        Assert.Equal(VaultErrorKind.ConfigurationError, result.ErrorKind);
        Assert.Contains("AWS_REGION", result.ErrorMessage);
    }

    [Fact]
    public void CreateClient_WhitespaceEnvVar_ReturnsConfigurationError()
    {
        Environment.SetEnvironmentVariable("AWS_REGION", "   ");

        var result = AwsAuthFactory.CreateClient();

        Assert.False(result.IsSuccess);
        Assert.Equal(VaultErrorKind.ConfigurationError, result.ErrorKind);
    }

    [Fact]
    public void CreateClient_ValidRegion_ReturnsSuccess()
    {
        Environment.SetEnvironmentVariable("AWS_REGION", "us-east-1");

        var result = AwsAuthFactory.CreateClient();

        Assert.True(result.IsSuccess);
        Assert.NotNull(result.Value);
        result.Value.Dispose();
    }

    [Fact]
    public void CreateClient_ValidRegion_ReturnsDisposableClient()
    {
        Environment.SetEnvironmentVariable("AWS_REGION", "eu-west-1");

        var result = AwsAuthFactory.CreateClient();

        Assert.True(result.IsSuccess);
        var ex = Record.Exception(() => result.Value.Dispose());
        Assert.Null(ex);
    }
}
