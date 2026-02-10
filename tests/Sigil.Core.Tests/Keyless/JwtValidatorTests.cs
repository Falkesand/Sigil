using Sigil.Keyless;

namespace Sigil.Core.Tests.Keyless;

public class JwtValidatorTests : IDisposable
{
    private HttpClient? _httpClient;
    private JwksClient? _jwksClient;
    private JwtValidator? _validator;

    [Fact]
    public async Task ValidateAsync_ValidRs256_Succeeds()
    {
        var (jwt, key) = TestJwtBuilder.CreateRs256Token(
            "https://test.example.com", "user@test.com", "sigil:sha256:abc123");

        var handler = TestJwtBuilder.CreateJwksHandler(key, "test-kid");
        CreateValidator(handler);

        var result = await _validator!.ValidateAsync(jwt, "sigil:sha256:abc123");

        Assert.True(result.IsSuccess);
        Assert.Equal("user@test.com", result.Value.Subject);
        Assert.Equal("https://test.example.com", result.Value.Issuer);
        key.Dispose();
    }

    [Fact]
    public async Task ValidateAsync_ValidEs256_Succeeds()
    {
        var (jwt, key) = TestJwtBuilder.CreateEs256Token(
            "https://test.example.com", "repo:org/repo", "sigil:sha256:def456",
            kid: "test-kid-ec");

        var handler = TestJwtBuilder.CreateJwksHandler(key, "test-kid-ec");
        CreateValidator(handler);

        var result = await _validator!.ValidateAsync(jwt, "sigil:sha256:def456");

        Assert.True(result.IsSuccess);
        Assert.Equal("repo:org/repo", result.Value.Subject);
        key.Dispose();
    }

    [Fact]
    public async Task ValidateAsync_Expired_Fails()
    {
        var (jwt, key) = TestJwtBuilder.CreateRs256Token(
            "https://test.example.com", "user", "aud",
            expiration: DateTimeOffset.UtcNow.AddHours(-2));

        var handler = TestJwtBuilder.CreateJwksHandler(key, "test-kid");
        CreateValidator(handler);

        var result = await _validator!.ValidateAsync(jwt, "aud");

        Assert.False(result.IsSuccess);
        Assert.Equal(KeylessErrorKind.TokenExpired, result.ErrorKind);
        key.Dispose();
    }

    [Fact]
    public async Task ValidateAsync_WrongAudience_Fails()
    {
        var (jwt, key) = TestJwtBuilder.CreateRs256Token(
            "https://test.example.com", "user", "wrong-audience");

        var handler = TestJwtBuilder.CreateJwksHandler(key, "test-kid");
        CreateValidator(handler);

        var result = await _validator!.ValidateAsync(jwt, "expected-audience");

        Assert.False(result.IsSuccess);
        Assert.Equal(KeylessErrorKind.AudienceMismatch, result.ErrorKind);
        key.Dispose();
    }

    [Fact]
    public async Task ValidateAsync_InvalidSignature_Fails()
    {
        var (jwt, key) = TestJwtBuilder.CreateRs256Token(
            "https://test.example.com", "user", "aud");

        // Use a different key for JWKS (signature won't verify)
        using var wrongKey = System.Security.Cryptography.RSA.Create(2048);
        var handler = TestJwtBuilder.CreateJwksHandler(wrongKey, "test-kid");
        CreateValidator(handler);

        var result = await _validator!.ValidateAsync(jwt, "aud");

        Assert.False(result.IsSuccess);
        Assert.Equal(KeylessErrorKind.TokenValidationFailed, result.ErrorKind);
        key.Dispose();
    }

    [Fact]
    public async Task ValidateAsync_UnknownKid_Fails()
    {
        var (jwt, key) = TestJwtBuilder.CreateRs256Token(
            "https://test.example.com", "user", "aud", kid: "unknown-kid");

        var handler = TestJwtBuilder.CreateJwksHandler(key, "different-kid");
        CreateValidator(handler);

        var result = await _validator!.ValidateAsync(jwt, "aud");

        Assert.False(result.IsSuccess);
        Assert.Equal(KeylessErrorKind.TokenValidationFailed, result.ErrorKind);
        Assert.Contains("No matching key", result.ErrorMessage);
        key.Dispose();
    }

    [Fact]
    public async Task ValidateAsync_MissingIssuer_Fails()
    {
        // Create a manually crafted token without iss claim
        var header = System.Text.Json.JsonSerializer.Serialize(
            new { alg = "RS256", typ = "JWT", kid = "k1" });
        var payload = System.Text.Json.JsonSerializer.Serialize(
            new { sub = "user", aud = "aud", exp = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds() });

        var headerB64 = JwtParser.Base64UrlEncode(System.Text.Encoding.UTF8.GetBytes(header));
        var payloadB64 = JwtParser.Base64UrlEncode(System.Text.Encoding.UTF8.GetBytes(payload));
        var sigB64 = JwtParser.Base64UrlEncode([(byte)0]);

        using var key = System.Security.Cryptography.RSA.Create(2048);
        var handler = TestJwtBuilder.CreateJwksHandler(key, "k1");
        CreateValidator(handler);

        var result = await _validator!.ValidateAsync($"{headerB64}.{payloadB64}.{sigB64}", "aud");

        Assert.False(result.IsSuccess);
        Assert.Equal(KeylessErrorKind.TokenValidationFailed, result.ErrorKind);
        Assert.Contains("iss", result.ErrorMessage);
    }

    [Fact]
    public async Task ValidateAsync_ClockSkew60s_Tolerated()
    {
        // Token expired 30 seconds ago — within 60s clock skew
        var (jwt, key) = TestJwtBuilder.CreateRs256Token(
            "https://test.example.com", "user", "aud",
            expiration: DateTimeOffset.UtcNow.AddSeconds(-30));

        var handler = TestJwtBuilder.CreateJwksHandler(key, "test-kid");
        CreateValidator(handler);

        var result = await _validator!.ValidateAsync(jwt, "aud");

        Assert.True(result.IsSuccess);
        key.Dispose();
    }

    private void CreateValidator(HttpMessageHandler handler)
    {
        _httpClient = new HttpClient(handler);
        _jwksClient = new JwksClient(_httpClient);
        _validator = new JwtValidator(_jwksClient);
    }

    public void Dispose()
    {
        _validator?.Dispose();
        _jwksClient?.Dispose();
        _httpClient?.Dispose();
    }
}
