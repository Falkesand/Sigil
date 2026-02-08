using Sigil.Vault;
using Sigil.Vault.Aws;

namespace Sigil.Vault.Aws.Tests;

[Collection("AwsEnvironment")]
public class AwsKmsKeyProviderTests : IDisposable
{
    private readonly string? _originalRegion;

    public AwsKmsKeyProviderTests()
    {
        _originalRegion = Environment.GetEnvironmentVariable("AWS_REGION");
    }

    public void Dispose()
    {
        Environment.SetEnvironmentVariable("AWS_REGION", _originalRegion);
    }

    [Fact]
    public void Create_MissingRegion_ReturnsConfigurationError()
    {
        Environment.SetEnvironmentVariable("AWS_REGION", null);

        var result = AwsKmsKeyProvider.Create();

        Assert.False(result.IsSuccess);
        Assert.Equal(VaultErrorKind.ConfigurationError, result.ErrorKind);
    }

    [Fact]
    public async Task Create_ValidRegion_ReturnsSuccess()
    {
        Environment.SetEnvironmentVariable("AWS_REGION", "us-east-1");

        var result = AwsKmsKeyProvider.Create();

        Assert.True(result.IsSuccess);
        Assert.NotNull(result.Value);
        await result.Value.DisposeAsync();
    }

    [Fact]
    public async Task GetSignerAsync_EmptyKeyReference_ReturnsInvalidKeyReference()
    {
        Environment.SetEnvironmentVariable("AWS_REGION", "us-east-1");
        var providerResult = AwsKmsKeyProvider.Create();
        Assert.True(providerResult.IsSuccess);

        await using var provider = providerResult.Value;

        var result = await provider.GetSignerAsync("");

        Assert.False(result.IsSuccess);
        Assert.Equal(VaultErrorKind.InvalidKeyReference, result.ErrorKind);
    }

    [Fact]
    public async Task GetSignerAsync_NullKeyReference_ReturnsInvalidKeyReference()
    {
        Environment.SetEnvironmentVariable("AWS_REGION", "us-east-1");
        var providerResult = AwsKmsKeyProvider.Create();
        Assert.True(providerResult.IsSuccess);

        await using var provider = providerResult.Value;

        var result = await provider.GetSignerAsync(null!);

        Assert.False(result.IsSuccess);
        Assert.Equal(VaultErrorKind.InvalidKeyReference, result.ErrorKind);
    }

    [Fact]
    public async Task GetSignerAsync_WhitespaceKeyReference_ReturnsInvalidKeyReference()
    {
        Environment.SetEnvironmentVariable("AWS_REGION", "us-east-1");
        var providerResult = AwsKmsKeyProvider.Create();
        Assert.True(providerResult.IsSuccess);

        await using var provider = providerResult.Value;

        var result = await provider.GetSignerAsync("   ");

        Assert.False(result.IsSuccess);
        Assert.Equal(VaultErrorKind.InvalidKeyReference, result.ErrorKind);
    }

    [Fact]
    public async Task DisposeAsync_CanBeCalledMultipleTimes()
    {
        Environment.SetEnvironmentVariable("AWS_REGION", "us-east-1");
        var providerResult = AwsKmsKeyProvider.Create();
        Assert.True(providerResult.IsSuccess);
        var provider = providerResult.Value;

        await provider.DisposeAsync();
        var ex = await Record.ExceptionAsync(async () => await provider.DisposeAsync());

        Assert.Null(ex);
    }

    [Fact]
    public async Task GetSignerAsync_AfterDispose_ReturnsConfigurationError()
    {
        Environment.SetEnvironmentVariable("AWS_REGION", "us-east-1");
        var providerResult = AwsKmsKeyProvider.Create();
        Assert.True(providerResult.IsSuccess);
        var provider = providerResult.Value;

        await provider.DisposeAsync();

        var result = await provider.GetSignerAsync("some-key");

        Assert.False(result.IsSuccess);
        Assert.Equal(VaultErrorKind.ConfigurationError, result.ErrorKind);
        Assert.Contains("disposed", result.ErrorMessage);
    }

    [Fact]
    public async Task GetPublicKeyAsync_EmptyKeyReference_ReturnsInvalidKeyReference()
    {
        Environment.SetEnvironmentVariable("AWS_REGION", "us-east-1");
        var providerResult = AwsKmsKeyProvider.Create();
        Assert.True(providerResult.IsSuccess);

        await using var provider = providerResult.Value;

        var result = await provider.GetPublicKeyAsync("");

        Assert.False(result.IsSuccess);
        Assert.Equal(VaultErrorKind.InvalidKeyReference, result.ErrorKind);
    }

    [Fact]
    public async Task ImplementsIKeyProvider()
    {
        Environment.SetEnvironmentVariable("AWS_REGION", "us-east-1");
        var providerResult = AwsKmsKeyProvider.Create();
        Assert.True(providerResult.IsSuccess);

        var provider = providerResult.Value;

        Assert.IsAssignableFrom<IKeyProvider>(provider);

        await provider.DisposeAsync();
    }
}
