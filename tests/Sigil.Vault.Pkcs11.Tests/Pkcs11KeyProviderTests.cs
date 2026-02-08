using Sigil.Vault;
using Sigil.Vault.Pkcs11;

namespace Sigil.Vault.Pkcs11.Tests;

public class Pkcs11KeyProviderTests
{
    [Fact]
    public void Create_NullLibraryPath_ReturnsFail()
    {
        var result = Pkcs11KeyProvider.Create(null!, null);

        Assert.False(result.IsSuccess);
        Assert.Equal(VaultErrorKind.ConfigurationError, result.ErrorKind);
    }

    [Fact]
    public void Create_EmptyLibraryPath_ReturnsFail()
    {
        var result = Pkcs11KeyProvider.Create("", null);

        Assert.False(result.IsSuccess);
        Assert.Equal(VaultErrorKind.ConfigurationError, result.ErrorKind);
    }

    [Fact]
    public void Create_WithLibraryPath_ReturnsSuccess()
    {
        // Note: the library isn't loaded until GetSignerAsync/GetPublicKeyAsync is called (lazy)
        var result = Pkcs11KeyProvider.Create("/path/to/nonexistent/lib.so", null);

        Assert.True(result.IsSuccess);
        Assert.NotNull(result.Value);
    }

    [Fact]
    public void Create_WithPin_ReturnsSuccess()
    {
        var result = Pkcs11KeyProvider.Create("/path/to/lib.so", "1234");

        Assert.True(result.IsSuccess);
    }

    [Fact]
    public void Create_ImplementsIKeyProvider()
    {
        var result = Pkcs11KeyProvider.Create("/path/to/lib.so", null);

        Assert.True(result.IsSuccess);
        Assert.IsAssignableFrom<IKeyProvider>(result.Value);
    }

    [Fact]
    public async Task GetSignerAsync_InvalidLibrary_ReturnsNetworkError()
    {
        var result = Pkcs11KeyProvider.Create("/nonexistent/lib.so", null);
        Assert.True(result.IsSuccess);

        await using var provider = result.Value;
        var signerResult = await provider.GetSignerAsync("pkcs11:token=Test;object=key1");

        Assert.False(signerResult.IsSuccess);
        // Library load failure maps to NetworkError (infrastructure issue)
        Assert.Equal(VaultErrorKind.NetworkError, signerResult.ErrorKind);
    }

    [Fact]
    public async Task GetPublicKeyAsync_InvalidLibrary_ReturnsNetworkError()
    {
        var result = Pkcs11KeyProvider.Create("/nonexistent/lib.so", null);
        Assert.True(result.IsSuccess);

        await using var provider = result.Value;
        var keyResult = await provider.GetPublicKeyAsync("pkcs11:token=Test;object=key1");

        Assert.False(keyResult.IsSuccess);
        Assert.Equal(VaultErrorKind.NetworkError, keyResult.ErrorKind);
    }

    [Fact]
    public async Task GetSignerAsync_EmptyKeyReference_ReturnsInvalidKeyReference()
    {
        var result = Pkcs11KeyProvider.Create("/path/to/lib.so", null);
        Assert.True(result.IsSuccess);

        await using var provider = result.Value;
        var signerResult = await provider.GetSignerAsync("");

        Assert.False(signerResult.IsSuccess);
        Assert.Equal(VaultErrorKind.InvalidKeyReference, signerResult.ErrorKind);
    }

    [Fact]
    public async Task GetPublicKeyAsync_EmptyKeyReference_ReturnsInvalidKeyReference()
    {
        var result = Pkcs11KeyProvider.Create("/path/to/lib.so", null);
        Assert.True(result.IsSuccess);

        await using var provider = result.Value;
        var keyResult = await provider.GetPublicKeyAsync("");

        Assert.False(keyResult.IsSuccess);
        Assert.Equal(VaultErrorKind.InvalidKeyReference, keyResult.ErrorKind);
    }

    [Fact]
    public async Task GetSignerAsync_InvalidScheme_ReturnsInvalidKeyReference()
    {
        var result = Pkcs11KeyProvider.Create("/path/to/lib.so", null);
        Assert.True(result.IsSuccess);

        await using var provider = result.Value;
        var signerResult = await provider.GetSignerAsync("https://example.com");

        Assert.False(signerResult.IsSuccess);
        Assert.Equal(VaultErrorKind.InvalidKeyReference, signerResult.ErrorKind);
    }

    [Fact]
    public async Task DisposeAsync_DoesNotThrow()
    {
        var result = Pkcs11KeyProvider.Create("/path/to/lib.so", null);
        Assert.True(result.IsSuccess);

        var ex = await Record.ExceptionAsync(async () => await result.Value.DisposeAsync());

        Assert.Null(ex);
    }

    [Fact]
    public async Task DisposeAsync_CanBeCalledMultipleTimes()
    {
        var result = Pkcs11KeyProvider.Create("/path/to/lib.so", null);
        Assert.True(result.IsSuccess);

        var provider = result.Value;
        var ex = await Record.ExceptionAsync(async () =>
        {
            await provider.DisposeAsync();
            await provider.DisposeAsync();
        });

        Assert.Null(ex);
    }

    [Fact]
    public void CreateFromEnvironment_NoEnvVars_ReturnsFail()
    {
        // Temporarily clear env vars for this test
        var savedLib = Environment.GetEnvironmentVariable("PKCS11_LIBRARY");
        try
        {
            Environment.SetEnvironmentVariable("PKCS11_LIBRARY", null);

            var result = Pkcs11KeyProvider.CreateFromEnvironment();

            Assert.False(result.IsSuccess);
            Assert.Equal(VaultErrorKind.ConfigurationError, result.ErrorKind);
            Assert.Contains("PKCS11_LIBRARY", result.ErrorMessage);
        }
        finally
        {
            Environment.SetEnvironmentVariable("PKCS11_LIBRARY", savedLib);
        }
    }

    [Fact]
    public void CreateFromEnvironment_WithEnvVars_ReturnsSuccess()
    {
        var savedLib = Environment.GetEnvironmentVariable("PKCS11_LIBRARY");
        var savedPin = Environment.GetEnvironmentVariable("PKCS11_PIN");
        try
        {
            Environment.SetEnvironmentVariable("PKCS11_LIBRARY", "/path/to/lib.so");
            Environment.SetEnvironmentVariable("PKCS11_PIN", "1234");

            var result = Pkcs11KeyProvider.CreateFromEnvironment();

            Assert.True(result.IsSuccess);
        }
        finally
        {
            Environment.SetEnvironmentVariable("PKCS11_LIBRARY", savedLib);
            Environment.SetEnvironmentVariable("PKCS11_PIN", savedPin);
        }
    }

    [Fact]
    public async Task GetSignerAsync_PlainKeyLabel_ParsesAsDefaultUri()
    {
        // A plain key label (not pkcs11: URI) should still be accepted
        // but will fail due to invalid library path
        var result = Pkcs11KeyProvider.Create("/nonexistent/lib.so", null);
        Assert.True(result.IsSuccess);

        await using var provider = result.Value;
        var signerResult = await provider.GetSignerAsync("my-signing-key");

        // Should fail at library load, not at key reference parsing
        Assert.False(signerResult.IsSuccess);
        Assert.Equal(VaultErrorKind.NetworkError, signerResult.ErrorKind);
    }
}
