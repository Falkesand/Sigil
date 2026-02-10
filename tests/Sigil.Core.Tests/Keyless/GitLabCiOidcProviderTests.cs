using Sigil.Keyless;

namespace Sigil.Core.Tests.Keyless;

public class GitLabCiOidcProviderTests
{
    [Fact]
    public async Task AcquireTokenAsync_ReturnsStoredToken()
    {
        var provider = new GitLabCiOidcProvider("my-gitlab-jwt");

        var result = await provider.AcquireTokenAsync("sigil:sha256:abc123");

        Assert.True(result.IsSuccess);
        Assert.Equal("my-gitlab-jwt", result.Value);
    }

    [Fact]
    public async Task AcquireTokenAsync_IgnoresAudienceParameter()
    {
        var provider = new GitLabCiOidcProvider("fixed-token");

        var result1 = await provider.AcquireTokenAsync("sigil:sha256:abc");
        var result2 = await provider.AcquireTokenAsync("completely-different-audience");

        Assert.True(result1.IsSuccess);
        Assert.True(result2.IsSuccess);
        Assert.Equal(result1.Value, result2.Value);
    }

    [Fact]
    public void Constructor_NullToken_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new GitLabCiOidcProvider(null!));
    }

    [Fact]
    public void Constructor_EmptyToken_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => new GitLabCiOidcProvider(""));
    }

    [Fact]
    public void Constructor_WhitespaceToken_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => new GitLabCiOidcProvider("   "));
    }

    [Fact]
    public void ProviderName_IsGitLabCI()
    {
        var provider = new GitLabCiOidcProvider("token");

        Assert.Equal("GitLab CI", provider.ProviderName);
    }
}
