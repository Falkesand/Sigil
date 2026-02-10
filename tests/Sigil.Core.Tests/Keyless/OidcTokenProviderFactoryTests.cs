using Sigil.Keyless;

namespace Sigil.Core.Tests.Keyless;

public class OidcTokenProviderFactoryTests
{
    [Fact]
    public void Create_ManualToken_ReturnsManualProvider()
    {
        var result = OidcTokenProviderFactory.Create("my-token");

        Assert.True(result.IsSuccess);
        Assert.IsType<ManualOidcTokenProvider>(result.Value);
        Assert.Equal("Manual", result.Value.ProviderName);
    }

    [Fact]
    public void Create_NoEnvVars_Fails()
    {
        var result = OidcTokenProviderFactory.Create();

        Assert.False(result.IsSuccess);
        Assert.Equal(KeylessErrorKind.ConfigurationError, result.ErrorKind);
    }

    [Fact]
    public void Create_ManualTokenTakesPriority()
    {
        // Even if env vars were set, manual token should take priority
        var result = OidcTokenProviderFactory.Create("explicit-token");

        Assert.True(result.IsSuccess);
        Assert.IsType<ManualOidcTokenProvider>(result.Value);
    }
}
