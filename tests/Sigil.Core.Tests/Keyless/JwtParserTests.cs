using System.Text;
using System.Text.Json;
using Sigil.Keyless;

namespace Sigil.Core.Tests.Keyless;

public class JwtParserTests
{
    [Fact]
    public void Parse_ValidRs256Token_Succeeds()
    {
        var (jwt, key) = TestJwtBuilder.CreateRs256Token(
            "https://test.example.com", "user@test.com", "sigil:sha256:abc123");

        var result = JwtParser.Parse(jwt);

        Assert.True(result.IsSuccess);
        Assert.Equal("RS256", result.Value.Algorithm);
        Assert.Equal("https://test.example.com", result.Value.Issuer);
        Assert.Equal("user@test.com", result.Value.Subject);
        Assert.Equal("sigil:sha256:abc123", result.Value.Audience);
        Assert.NotNull(result.Value.ExpirationUnix);
        key.Dispose();
    }

    [Fact]
    public void Parse_ValidEs256Token_Succeeds()
    {
        var (jwt, key) = TestJwtBuilder.CreateEs256Token(
            "https://actions.example.com", "repo:org/repo", "sigil:sha256:def456");

        var result = JwtParser.Parse(jwt);

        Assert.True(result.IsSuccess);
        Assert.Equal("ES256", result.Value.Algorithm);
        Assert.Equal("https://actions.example.com", result.Value.Issuer);
        Assert.Equal("repo:org/repo", result.Value.Subject);
        key.Dispose();
    }

    [Fact]
    public void Parse_EmptyString_Fails()
    {
        var result = JwtParser.Parse("");

        Assert.False(result.IsSuccess);
        Assert.Equal(KeylessErrorKind.TokenParsingFailed, result.ErrorKind);
    }

    [Fact]
    public void Parse_TwoParts_Fails()
    {
        var result = JwtParser.Parse("part1.part2");

        Assert.False(result.IsSuccess);
        Assert.Equal(KeylessErrorKind.TokenParsingFailed, result.ErrorKind);
        Assert.Contains("3 parts", result.ErrorMessage);
    }

    [Fact]
    public void Parse_BadBase64UrlHeader_Fails()
    {
        var result = JwtParser.Parse("!!!.eyJ0ZXN0IjoxfQ.signature");

        Assert.False(result.IsSuccess);
        Assert.Equal(KeylessErrorKind.TokenParsingFailed, result.ErrorKind);
    }

    [Fact]
    public void Parse_BadJsonHeader_Fails()
    {
        var notJson = JwtParser.Base64UrlEncode(Encoding.UTF8.GetBytes("not json"));
        var payload = JwtParser.Base64UrlEncode(Encoding.UTF8.GetBytes("{}"));
        var sig = JwtParser.Base64UrlEncode([(byte)1, 2, 3]);

        var result = JwtParser.Parse($"{notJson}.{payload}.{sig}");

        Assert.False(result.IsSuccess);
        Assert.Contains("Header", result.ErrorMessage);
    }

    [Fact]
    public void Parse_BadJsonPayload_Fails()
    {
        var header = JwtParser.Base64UrlEncode(Encoding.UTF8.GetBytes("{\"alg\":\"RS256\"}"));
        var notJson = JwtParser.Base64UrlEncode(Encoding.UTF8.GetBytes("not json"));
        var sig = JwtParser.Base64UrlEncode([(byte)1, 2, 3]);

        var result = JwtParser.Parse($"{header}.{notJson}.{sig}");

        Assert.False(result.IsSuccess);
        Assert.Contains("Payload", result.ErrorMessage);
    }

    [Fact]
    public void Parse_Base64UrlPadding_Handled()
    {
        // Create a token where base64url needs padding (lengths not multiple of 4)
        var (jwt, key) = TestJwtBuilder.CreateRs256Token(
            "https://test.example.com", "u", "a");

        var result = JwtParser.Parse(jwt);

        Assert.True(result.IsSuccess);
        key.Dispose();
    }

    [Fact]
    public void Parse_AudienceAsString_Extracted()
    {
        var (jwt, key) = TestJwtBuilder.CreateRs256Token(
            "https://test.example.com", "sub", "my-audience");

        var result = JwtParser.Parse(jwt);

        Assert.True(result.IsSuccess);
        Assert.Equal("my-audience", result.Value.Audience);
        key.Dispose();
    }

    [Fact]
    public void Parse_AudienceAsArray_ExtractsFirst()
    {
        var header = JsonSerializer.Serialize(new { alg = "RS256", typ = "JWT", kid = "k1" });
        string[] audiences = ["aud1", "aud2"];
        var payload = JsonSerializer.Serialize(new
        {
            iss = "https://test.example.com",
            sub = "user",
            aud = audiences,
            exp = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds()
        });

        var headerB64 = JwtParser.Base64UrlEncode(Encoding.UTF8.GetBytes(header));
        var payloadB64 = JwtParser.Base64UrlEncode(Encoding.UTF8.GetBytes(payload));
        var sigB64 = JwtParser.Base64UrlEncode([0]);

        var result = JwtParser.Parse($"{headerB64}.{payloadB64}.{sigB64}");

        Assert.True(result.IsSuccess);
        Assert.Equal("aud1", result.Value.Audience);
    }

    [Fact]
    public void Parse_SigningInput_Correct()
    {
        var (jwt, key) = TestJwtBuilder.CreateRs256Token(
            "https://test.example.com", "sub", "aud");
        var parts = jwt.Split('.');

        var result = JwtParser.Parse(jwt);

        Assert.True(result.IsSuccess);
        Assert.Equal($"{parts[0]}.{parts[1]}", result.Value.SigningInput);
        key.Dispose();
    }
}
