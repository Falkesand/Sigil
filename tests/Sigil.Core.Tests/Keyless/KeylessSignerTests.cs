using Sigil.Crypto;
using Sigil.Keyless;
using Sigil.Keys;

namespace Sigil.Core.Tests.Keyless;

public class KeylessSignerTests
{
    [Fact]
    public async Task CreateAsync_Success_SetsKeyAndMetadata()
    {
        var (jwt, key) = TestJwtBuilder.CreateRs256Token(
            "https://token.actions.githubusercontent.com",
            "repo:org/repo:ref:refs/heads/main",
            "placeholder");
        key.Dispose();

        // ManualOidcTokenProvider ignores audience, returns the token as-is
        var provider = new ManualOidcTokenProvider(jwt);

        var result = await KeylessSigner.CreateAsync(provider);

        Assert.True(result.IsSuccess);
        using var signer = result.Value;

        Assert.NotNull(signer.Signer);
        Assert.NotNull(signer.Signer.PublicKey);
        Assert.Equal("https://token.actions.githubusercontent.com", signer.OidcIssuer);
        Assert.Equal("repo:org/repo:ref:refs/heads/main", signer.OidcIdentity);
        Assert.Equal(jwt, signer.OidcToken);
    }

    [Fact]
    public async Task CreateAsync_AudienceFormat_ContainsFingerprint()
    {
        // We can verify that the audience requested contains the key fingerprint
        string? capturedAudience = null;
        var provider = new AudienceCapturingProvider(aud =>
        {
            capturedAudience = aud;
        });

        var result = await KeylessSigner.CreateAsync(provider);

        // The provider returns a valid JWT, so CreateAsync should work
        Assert.True(result.IsSuccess);
        using var signer = result.Value;

        Assert.NotNull(capturedAudience);
        Assert.StartsWith("sigil:sha256:", capturedAudience);
    }

    [Fact]
    public async Task CreateAsync_TokenFail_Propagates()
    {
        var provider = new FailingOidcProvider();

        var result = await KeylessSigner.CreateAsync(provider);

        Assert.False(result.IsSuccess);
        Assert.Equal(KeylessErrorKind.TokenAcquisitionFailed, result.ErrorKind);
    }

    [Fact]
    public async Task CreateAsync_InvalidToken_FailsOnParse()
    {
        var provider = new ManualOidcTokenProvider("not-a-jwt");

        var result = await KeylessSigner.CreateAsync(provider);

        Assert.False(result.IsSuccess);
        Assert.Equal(KeylessErrorKind.TokenParsingFailed, result.ErrorKind);
    }

    [Fact]
    public async Task Dispose_DisposesUnderlyingSigner()
    {
        var (jwt, key) = TestJwtBuilder.CreateRs256Token(
            "https://issuer.example.com", "subject", "placeholder");
        key.Dispose();

        var provider = new ManualOidcTokenProvider(jwt);
        var result = await KeylessSigner.CreateAsync(provider);

        Assert.True(result.IsSuccess);
        var signer = result.Value;

        // Should not throw
        signer.Dispose();

        // After dispose, accessing the signer's underlying key should throw
        Assert.ThrowsAny<Exception>(() => signer.Signer.Sign(new byte[] { 1 }));
    }

    private sealed class AudienceCapturingProvider : IOidcTokenProvider
    {
        private readonly Action<string> _captureAudience;

        public string ProviderName => "Test";

        public AudienceCapturingProvider(Action<string> captureAudience)
        {
            _captureAudience = captureAudience;
        }

        public Task<KeylessResult<string>> AcquireTokenAsync(string audience, CancellationToken ct = default)
        {
            _captureAudience(audience);
            // Return a valid JWT for this test
            var (jwt, key) = TestJwtBuilder.CreateRs256Token(
                "https://issuer.example.com", "subject", audience);
            key.Dispose();
            return Task.FromResult(KeylessResult<string>.Ok(jwt));
        }
    }

    private sealed class FailingOidcProvider : IOidcTokenProvider
    {
        public string ProviderName => "Failing";

        public Task<KeylessResult<string>> AcquireTokenAsync(string audience, CancellationToken ct = default)
        {
            return Task.FromResult(KeylessResult<string>.Fail(
                KeylessErrorKind.TokenAcquisitionFailed, "Provider failed"));
        }
    }
}
