using Sigil.Oci;

namespace Sigil.Core.Tests.Oci;

public class ImageReferenceTests
{
    [Fact]
    public void Parse_full_reference_with_tag()
    {
        var result = ImageReference.Parse("registry.example.com/repo:tag");

        Assert.True(result.IsSuccess);
        Assert.Equal("registry.example.com", result.Value.Registry);
        Assert.Equal("repo", result.Value.RepositoryPath);
        Assert.Equal("tag", result.Value.Tag);
        Assert.Null(result.Value.Digest);
    }

    [Fact]
    public void Parse_digest_reference()
    {
        var digest = "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        var result = ImageReference.Parse($"registry.example.com/repo@{digest}");

        Assert.True(result.IsSuccess);
        Assert.Equal("registry.example.com", result.Value.Registry);
        Assert.Equal("repo", result.Value.RepositoryPath);
        Assert.Null(result.Value.Tag);
        Assert.Equal(digest, result.Value.Digest);
    }

    [Fact]
    public void Parse_docker_hub_library_image()
    {
        var result = ImageReference.Parse("alpine");

        Assert.True(result.IsSuccess);
        Assert.Equal("docker.io", result.Value.Registry);
        Assert.Equal("library/alpine", result.Value.RepositoryPath);
        Assert.Equal("latest", result.Value.Tag);
    }

    [Fact]
    public void Parse_docker_hub_user_repo()
    {
        var result = ImageReference.Parse("myrepo/myimage");

        Assert.True(result.IsSuccess);
        Assert.Equal("docker.io", result.Value.Registry);
        Assert.Equal("myrepo/myimage", result.Value.RepositoryPath);
        Assert.Equal("latest", result.Value.Tag);
    }

    [Fact]
    public void Parse_multi_level_path()
    {
        var result = ImageReference.Parse("ghcr.io/owner/repo/image:v1");

        Assert.True(result.IsSuccess);
        Assert.Equal("ghcr.io", result.Value.Registry);
        Assert.Equal("owner/repo/image", result.Value.RepositoryPath);
        Assert.Equal("v1", result.Value.Tag);
    }

    [Fact]
    public void Parse_localhost_with_port()
    {
        var result = ImageReference.Parse("localhost:5000/test:latest");

        Assert.True(result.IsSuccess);
        Assert.Equal("localhost:5000", result.Value.Registry);
        Assert.Equal("test", result.Value.RepositoryPath);
        Assert.Equal("latest", result.Value.Tag);
    }

    [Fact]
    public void Parse_default_tag_when_omitted()
    {
        var result = ImageReference.Parse("ghcr.io/owner/repo");

        Assert.True(result.IsSuccess);
        Assert.Equal("latest", result.Value.Tag);
    }

    [Fact]
    public void ApiEndpoint_returns_docker_hub_endpoint()
    {
        var result = ImageReference.Parse("alpine");

        Assert.True(result.IsSuccess);
        Assert.Equal("https://registry-1.docker.io", result.Value.ApiEndpoint);
    }

    [Fact]
    public void ApiEndpoint_returns_https_for_other_registries()
    {
        var result = ImageReference.Parse("ghcr.io/owner/repo:v1");

        Assert.True(result.IsSuccess);
        Assert.Equal("https://ghcr.io", result.Value.ApiEndpoint);
    }

    [Fact]
    public void ApiEndpoint_returns_http_for_localhost()
    {
        var result = ImageReference.Parse("localhost:5000/test:latest");

        Assert.True(result.IsSuccess);
        Assert.Equal("http://localhost:5000", result.Value.ApiEndpoint);
    }

    [Fact]
    public void ApiEndpoint_returns_http_for_127_0_0_1()
    {
        var result = ImageReference.Parse("127.0.0.1:5000/test:latest");

        Assert.True(result.IsSuccess);
        Assert.Equal("http://127.0.0.1:5000", result.Value.ApiEndpoint);
    }

    [Fact]
    public void Parse_empty_string_fails()
    {
        var result = ImageReference.Parse("");

        Assert.False(result.IsSuccess);
        Assert.Equal(OciErrorKind.InvalidReference, result.ErrorKind);
    }

    [Fact]
    public void Parse_whitespace_fails()
    {
        var result = ImageReference.Parse("   ");

        Assert.False(result.IsSuccess);
        Assert.Equal(OciErrorKind.InvalidReference, result.ErrorKind);
    }

    [Fact]
    public void RepositoryPath_excludes_registry()
    {
        var result = ImageReference.Parse("myregistry.io/org/app:v2");

        Assert.True(result.IsSuccess);
        Assert.Equal("org/app", result.Value.RepositoryPath);
        Assert.DoesNotContain("myregistry.io", result.Value.RepositoryPath);
    }

    [Fact]
    public void FullName_reconstructs_tag_reference()
    {
        var result = ImageReference.Parse("ghcr.io/owner/repo:v1.0");

        Assert.True(result.IsSuccess);
        Assert.Equal("ghcr.io/owner/repo:v1.0", result.Value.FullName);
    }

    [Fact]
    public void FullName_reconstructs_digest_reference()
    {
        var digest = "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        var result = ImageReference.Parse($"ghcr.io/owner/repo@{digest}");

        Assert.True(result.IsSuccess);
        Assert.Equal($"ghcr.io/owner/repo@{digest}", result.Value.FullName);
    }

    [Fact]
    public void ManifestReference_returns_tag()
    {
        var result = ImageReference.Parse("ghcr.io/owner/repo:v1");

        Assert.True(result.IsSuccess);
        Assert.Equal("v1", result.Value.ManifestReference);
    }

    [Fact]
    public void ManifestReference_returns_digest()
    {
        var digest = "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        var result = ImageReference.Parse($"ghcr.io/owner/repo@{digest}");

        Assert.True(result.IsSuccess);
        Assert.Equal(digest, result.Value.ManifestReference);
    }

    [Fact]
    public void Parse_registry_with_port_and_tag()
    {
        var result = ImageReference.Parse("myregistry.io:8080/repo:v1");

        Assert.True(result.IsSuccess);
        Assert.Equal("myregistry.io:8080", result.Value.Registry);
        Assert.Equal("repo", result.Value.RepositoryPath);
        Assert.Equal("v1", result.Value.Tag);
    }
}
