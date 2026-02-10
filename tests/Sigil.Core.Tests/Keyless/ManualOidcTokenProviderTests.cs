using Sigil.Keyless;

namespace Sigil.Core.Tests.Keyless;

public class ManualOidcTokenProviderTests
{
    [Fact]
    public async Task AcquireTokenAsync_ReturnsStoredToken()
    {
        var provider = new ManualOidcTokenProvider("my-manual-token");

        var result = await provider.AcquireTokenAsync("any-audience");

        Assert.True(result.IsSuccess);
        Assert.Equal("my-manual-token", result.Value);
    }

    [Fact]
    public void Constructor_NullToken_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new ManualOidcTokenProvider(null!));
    }

    [Fact]
    public void Constructor_EmptyToken_Throws()
    {
        Assert.Throws<ArgumentException>(() => new ManualOidcTokenProvider(""));
    }

    [Fact]
    public void ProviderName_IsManual()
    {
        var provider = new ManualOidcTokenProvider("token");

        Assert.Equal("Manual", provider.ProviderName);
    }
}
