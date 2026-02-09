using Sigil.Oci;

namespace Sigil.Core.Tests.Oci;

public class CredentialHelperRunnerTests
{
    [Theory]
    [InlineData("helper;rm", false)]
    [InlineData("helper|bad", false)]
    [InlineData("helper&evil", false)]
    [InlineData("helper`cmd`", false)]
    [InlineData("helper$(cmd)", false)]
    [InlineData("helper name", false)]
    [InlineData("helper'quote", false)]
    [InlineData("helper\"quote", false)]
    [InlineData("valid-helper", true)]
    [InlineData("desktop", true)]
    [InlineData("ecr-login", true)]
    public void IsNameSafe_validates_helper_names(string name, bool expected)
    {
        Assert.Equal(expected, CredentialHelperRunner.IsNameSafe(name));
    }

    [Fact]
    public void IsNameSafe_rejects_empty()
    {
        Assert.False(CredentialHelperRunner.IsNameSafe(""));
    }

    [Fact]
    public void ParseHelperOutput_parses_credentials()
    {
        var json = """{"Username":"myuser","Secret":"mypass"}""";

        var result = CredentialHelperRunner.ParseHelperOutput(json);

        Assert.True(result.IsSuccess);
        Assert.Equal("myuser", result.Value.Username);
        Assert.Equal("mypass", result.Value.Password);
    }

    [Fact]
    public void ParseHelperOutput_invalid_json_fails()
    {
        var result = CredentialHelperRunner.ParseHelperOutput("not json");

        Assert.False(result.IsSuccess);
        Assert.Equal(OciErrorKind.AuthenticationFailed, result.ErrorKind);
    }

    [Fact]
    public void Get_rejects_unsafe_helper_names()
    {
        var result = CredentialHelperRunner.Get("bad;name", "ghcr.io");

        Assert.False(result.IsSuccess);
        Assert.Equal(OciErrorKind.AuthenticationFailed, result.ErrorKind);
        Assert.Contains("unsafe characters", result.ErrorMessage);
    }

    [Fact]
    public void Get_missing_helper_binary_fails()
    {
        // A helper that doesn't exist on the system
        var result = CredentialHelperRunner.Get("sigil-nonexistent-test-helper", "ghcr.io");

        Assert.False(result.IsSuccess);
        Assert.Equal(OciErrorKind.AuthenticationFailed, result.ErrorKind);
    }

    [Fact]
    public void FromBasicAuth_decodes_correctly()
    {
        var base64 = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("alice:secret123"));

        var creds = RegistryCredentials.FromBasicAuth(base64);

        Assert.Equal("alice", creds.Username);
        Assert.Equal("secret123", creds.Password);
    }

    [Fact]
    public void FromBasicAuth_handles_colon_in_password()
    {
        var base64 = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("user:pass:with:colons"));

        var creds = RegistryCredentials.FromBasicAuth(base64);

        Assert.Equal("user", creds.Username);
        Assert.Equal("pass:with:colons", creds.Password);
    }
}
