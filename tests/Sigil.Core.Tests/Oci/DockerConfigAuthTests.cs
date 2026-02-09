using Sigil.Oci;

namespace Sigil.Core.Tests.Oci;

public class DockerConfigAuthTests : IDisposable
{
    private readonly string _tempDir;

    public DockerConfigAuthTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"sigil-docker-config-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    private string WriteConfig(string json)
    {
        var path = Path.Combine(_tempDir, "config.json");
        File.WriteAllText(path, json);
        return path;
    }

    [Fact]
    public void Parses_auths_with_base64_credentials()
    {
        // "user:pass" in base64
        var base64 = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("user:pass"));
        var config = WriteConfig($$"""
            {
              "auths": {
                "ghcr.io": {
                  "auth": "{{base64}}"
                }
              }
            }
            """);

        var creds = DockerConfigAuth.Resolve("ghcr.io", config);

        Assert.NotNull(creds);
        Assert.Equal("user", creds.Username);
        Assert.Equal("pass", creds.Password);
    }

    [Fact]
    public void Missing_config_file_returns_null()
    {
        var result = DockerConfigAuth.Resolve("ghcr.io", Path.Combine(_tempDir, "nonexistent.json"));

        Assert.Null(result);
    }

    [Fact]
    public void Handles_docker_hub_key_variations()
    {
        var base64 = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("hubuser:hubpass"));
        var config = WriteConfig($$"""
            {
              "auths": {
                "https://index.docker.io/v1/": {
                  "auth": "{{base64}}"
                }
              }
            }
            """);

        var creds = DockerConfigAuth.Resolve("docker.io", config);

        Assert.NotNull(creds);
        Assert.Equal("hubuser", creds.Username);
    }

    [Fact]
    public void Handles_malformed_config_gracefully()
    {
        var config = WriteConfig("not valid json {{{");

        var result = DockerConfigAuth.Resolve("ghcr.io", config);

        Assert.Null(result);
    }

    [Fact]
    public void No_matching_registry_returns_null()
    {
        var base64 = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("u:p"));
        var config = WriteConfig($$"""
            {
              "auths": {
                "other.io": {
                  "auth": "{{base64}}"
                }
              }
            }
            """);

        var result = DockerConfigAuth.Resolve("ghcr.io", config);

        Assert.Null(result);
    }

    [Fact]
    public void Empty_auths_returns_null()
    {
        var config = WriteConfig("""
            {
              "auths": {}
            }
            """);

        var result = DockerConfigAuth.Resolve("ghcr.io", config);

        Assert.Null(result);
    }

    [Fact]
    public void Missing_auth_field_in_entry_returns_null()
    {
        var config = WriteConfig("""
            {
              "auths": {
                "ghcr.io": {}
              }
            }
            """);

        var result = DockerConfigAuth.Resolve("ghcr.io", config);

        Assert.Null(result);
    }
}
