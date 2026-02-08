using Sigil.Vault;
using Sigil.Vault.Azure;

namespace Sigil.Vault.Azure.Tests;

public class AzureAuthFactoryTests : IDisposable
{
    private readonly string? _originalValue;

    public AzureAuthFactoryTests()
    {
        _originalValue = Environment.GetEnvironmentVariable("AZURE_KEY_VAULT_URL");
    }

    public void Dispose()
    {
        // Restore original environment variable value
        Environment.SetEnvironmentVariable("AZURE_KEY_VAULT_URL", _originalValue);
    }

    [Fact]
    public void CreateFromEnvironment_MissingEnvVar_ReturnsConfigurationError()
    {
        Environment.SetEnvironmentVariable("AZURE_KEY_VAULT_URL", null);

        var result = AzureAuthFactory.CreateFromEnvironment();

        Assert.False(result.IsSuccess);
        Assert.Equal(VaultErrorKind.ConfigurationError, result.ErrorKind);
        Assert.Contains("AZURE_KEY_VAULT_URL", result.ErrorMessage);
    }

    [Fact]
    public void CreateFromEnvironment_EmptyEnvVar_ReturnsConfigurationError()
    {
        Environment.SetEnvironmentVariable("AZURE_KEY_VAULT_URL", "");

        var result = AzureAuthFactory.CreateFromEnvironment();

        Assert.False(result.IsSuccess);
        Assert.Equal(VaultErrorKind.ConfigurationError, result.ErrorKind);
        Assert.Contains("not set or empty", result.ErrorMessage);
    }

    [Fact]
    public void CreateFromEnvironment_WhitespaceEnvVar_ReturnsConfigurationError()
    {
        Environment.SetEnvironmentVariable("AZURE_KEY_VAULT_URL", "   ");

        var result = AzureAuthFactory.CreateFromEnvironment();

        Assert.False(result.IsSuccess);
        Assert.Equal(VaultErrorKind.ConfigurationError, result.ErrorKind);
    }

    [Fact]
    public void CreateFromEnvironment_InvalidUri_ReturnsConfigurationError()
    {
        Environment.SetEnvironmentVariable("AZURE_KEY_VAULT_URL", "not-a-valid-uri");

        var result = AzureAuthFactory.CreateFromEnvironment();

        Assert.False(result.IsSuccess);
        Assert.Equal(VaultErrorKind.ConfigurationError, result.ErrorKind);
        Assert.Contains("Invalid vault URL", result.ErrorMessage);
    }

    [Fact]
    public void CreateFromEnvironment_HttpNonLocalhost_ReturnsConfigurationError()
    {
        Environment.SetEnvironmentVariable("AZURE_KEY_VAULT_URL", "http://myvault.vault.azure.net");

        var result = AzureAuthFactory.CreateFromEnvironment();

        Assert.False(result.IsSuccess);
        Assert.Equal(VaultErrorKind.ConfigurationError, result.ErrorKind);
        Assert.Contains("HTTPS", result.ErrorMessage);
    }

    [Fact]
    public void CreateFromEnvironment_HttpsUrl_ReturnsSuccess()
    {
        Environment.SetEnvironmentVariable("AZURE_KEY_VAULT_URL", "https://myvault.vault.azure.net");

        var result = AzureAuthFactory.CreateFromEnvironment();

        Assert.True(result.IsSuccess);
        Assert.Equal(new Uri("https://myvault.vault.azure.net"), result.Value.VaultUri);
        Assert.NotNull(result.Value.Credential);
    }

    [Fact]
    public void CreateFromEnvironment_HttpLocalhost_ReturnsSuccess()
    {
        Environment.SetEnvironmentVariable("AZURE_KEY_VAULT_URL", "http://localhost:8080");

        var result = AzureAuthFactory.CreateFromEnvironment();

        Assert.True(result.IsSuccess);
        Assert.Equal(new Uri("http://localhost:8080"), result.Value.VaultUri);
    }

    [Fact]
    public void CreateFromEnvironment_Http127001_ReturnsSuccess()
    {
        Environment.SetEnvironmentVariable("AZURE_KEY_VAULT_URL", "http://127.0.0.1:8080");

        var result = AzureAuthFactory.CreateFromEnvironment();

        Assert.True(result.IsSuccess);
        Assert.Equal(new Uri("http://127.0.0.1:8080"), result.Value.VaultUri);
    }

    [Fact]
    public void CreateFromEnvironment_HttpIpv6Loopback_ReturnsSuccess()
    {
        Environment.SetEnvironmentVariable("AZURE_KEY_VAULT_URL", "http://[::1]:8080");

        var result = AzureAuthFactory.CreateFromEnvironment();

        Assert.True(result.IsSuccess);
    }
}
