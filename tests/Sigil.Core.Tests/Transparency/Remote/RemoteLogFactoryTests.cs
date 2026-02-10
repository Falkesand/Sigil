using Sigil.Transparency.Remote;

namespace Sigil.Core.Tests.Transparency.Remote;

public class RemoteLogFactoryTests
{
    [Fact]
    public void Rekor_shorthand_creates_RekorClient()
    {
        using var log = RemoteLogFactory.Create("rekor");

        Assert.IsType<RekorClient>(log);
        Assert.Equal("https://rekor.sigstore.dev", log.LogUrl);
    }

    [Fact]
    public void Rekor_shorthand_case_insensitive()
    {
        using var log = RemoteLogFactory.Create("Rekor");

        Assert.IsType<RekorClient>(log);
    }

    [Fact]
    public void Rekor_prefix_creates_custom_RekorClient()
    {
        using var log = RemoteLogFactory.Create("rekor:https://custom-rekor.example.com");

        Assert.IsType<RekorClient>(log);
        Assert.Equal("https://custom-rekor.example.com", log.LogUrl);
    }

    [Fact]
    public void Sigil_url_with_api_key_creates_SigilLogClient()
    {
        using var log = RemoteLogFactory.Create("https://log.example.com", "key123");

        Assert.IsType<SigilLogClient>(log);
        Assert.Equal("https://log.example.com", log.LogUrl);
    }

    [Fact]
    public void Sigil_url_without_api_key_throws()
    {
        Assert.Throws<ArgumentException>(() =>
            RemoteLogFactory.Create("https://log.example.com"));
    }

    [Fact]
    public void Sigil_url_with_empty_api_key_throws()
    {
        Assert.Throws<ArgumentException>(() =>
            RemoteLogFactory.Create("https://log.example.com", ""));
    }

    [Fact]
    public void Empty_url_throws()
    {
        Assert.Throws<ArgumentException>(() =>
            RemoteLogFactory.Create(""));
    }

    [Fact]
    public void Localhost_sigil_url_with_api_key_creates_SigilLogClient()
    {
        using var log = RemoteLogFactory.Create("http://localhost:5000", "key123");

        Assert.IsType<SigilLogClient>(log);
    }
}
