using System.Security.Cryptography;
using Sigil.Crypto;
using Sigil.Keyless;
using Sigil.Keys;
using Sigil.Signing;

namespace Sigil.Core.Tests.Keyless;

public class OidcVerifierTests : IDisposable
{
    private HttpClient? _httpClient;
    private JwksClient? _jwksClient;
    private JwtValidator? _jwtValidator;
    private OidcVerifier? _verifier;

    [Fact]
    public async Task VerifyAsync_ValidTokenAndAudience_Succeeds()
    {
        using var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var fingerprint = KeyFingerprint.Compute(signer.PublicKey);
        var audience = "sigil:" + fingerprint.Value;

        var (jwt, rsaKey) = TestJwtBuilder.CreateRs256Token(
            "https://test.example.com", "user@test.com", audience);

        var handler = TestJwtBuilder.CreateJwksHandler(rsaKey, "test-kid");
        CreateVerifier(handler);

        var entry = CreateEntry(signer, jwt);
        var result = await _verifier!.VerifyAsync(entry);

        Assert.True(result.IsValid);
        Assert.Equal("https://test.example.com", result.Issuer);
        Assert.Equal("user@test.com", result.Identity);
        rsaKey.Dispose();
    }

    [Fact]
    public async Task VerifyAsync_InvalidJwtSignature_Fails()
    {
        using var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var fingerprint = KeyFingerprint.Compute(signer.PublicKey);
        var audience = "sigil:" + fingerprint.Value;

        var (jwt, rsaKey) = TestJwtBuilder.CreateRs256Token(
            "https://test.example.com", "user", audience);

        // Use wrong key for JWKS
        using var wrongKey = RSA.Create(2048);
        var handler = TestJwtBuilder.CreateJwksHandler(wrongKey, "test-kid");
        CreateVerifier(handler);

        var entry = CreateEntry(signer, jwt);
        var result = await _verifier!.VerifyAsync(entry);

        Assert.False(result.IsValid);
        Assert.NotNull(result.Error);
        rsaKey.Dispose();
    }

    [Fact]
    public async Task VerifyAsync_WrongAudience_Fails()
    {
        using var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);

        // JWT has wrong audience (doesn't match the key fingerprint)
        var (jwt, rsaKey) = TestJwtBuilder.CreateRs256Token(
            "https://test.example.com", "user", "wrong-audience");

        var handler = TestJwtBuilder.CreateJwksHandler(rsaKey, "test-kid");
        CreateVerifier(handler);

        var entry = CreateEntry(signer, jwt);
        var result = await _verifier!.VerifyAsync(entry);

        Assert.False(result.IsValid);
        Assert.Contains("audience", result.Error, StringComparison.OrdinalIgnoreCase);
        rsaKey.Dispose();
    }

    [Fact]
    public async Task VerifyAsync_ExpiredToken_Fails()
    {
        using var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var fingerprint = KeyFingerprint.Compute(signer.PublicKey);
        var audience = "sigil:" + fingerprint.Value;

        var (jwt, rsaKey) = TestJwtBuilder.CreateRs256Token(
            "https://test.example.com", "user", audience,
            expiration: DateTimeOffset.UtcNow.AddHours(-2));

        var handler = TestJwtBuilder.CreateJwksHandler(rsaKey, "test-kid");
        CreateVerifier(handler);

        var entry = CreateEntry(signer, jwt);
        var result = await _verifier!.VerifyAsync(entry);

        Assert.False(result.IsValid);
        rsaKey.Dispose();
    }

    [Fact]
    public async Task VerifyAsync_NullOidcToken_Invalid()
    {
        var entry = new SignatureEntry
        {
            KeyId = "sha256:0000",
            Algorithm = "ecdsa-p256",
            PublicKey = "AAAA",
            Value = "AAAA",
            Timestamp = "2025-01-01T00:00:00Z",
            OidcToken = null
        };

        CreateVerifier(TestJwtBuilder.CreateJwksHandler(RSA.Create(2048), "k"));

        var result = await _verifier!.VerifyAsync(entry);

        Assert.False(result.IsValid);
        Assert.Contains("No OIDC token", result.Error);
    }

    [Fact]
    public async Task VerifyAsync_ExtractsIssuerAndIdentity()
    {
        using var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var fingerprint = KeyFingerprint.Compute(signer.PublicKey);
        var audience = "sigil:" + fingerprint.Value;

        var (jwt, rsaKey) = TestJwtBuilder.CreateRs256Token(
            "https://token.actions.githubusercontent.com",
            "repo:myorg/myrepo:ref:refs/heads/main",
            audience);

        var handler = TestJwtBuilder.CreateJwksHandler(rsaKey, "test-kid");
        CreateVerifier(handler);

        var entry = CreateEntry(signer, jwt);
        var result = await _verifier!.VerifyAsync(entry);

        Assert.True(result.IsValid);
        Assert.Equal("https://token.actions.githubusercontent.com", result.Issuer);
        Assert.Equal("repo:myorg/myrepo:ref:refs/heads/main", result.Identity);
        rsaKey.Dispose();
    }

    [Fact]
    public async Task VerifyAsync_JwksFetchFailure_Fails()
    {
        using var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var fingerprint = KeyFingerprint.Compute(signer.PublicKey);
        var audience = "sigil:" + fingerprint.Value;

        var (jwt, rsaKey) = TestJwtBuilder.CreateRs256Token(
            "https://test.example.com", "user", audience);

        // Create a handler that fails JWKS requests
        var handler = new FailingHandler();
        _httpClient = new HttpClient(handler);
        _jwksClient = new JwksClient(_httpClient);
        _jwtValidator = new JwtValidator(_jwksClient);
        _verifier = new OidcVerifier(_jwtValidator);

        var entry = CreateEntry(signer, jwt);
        var result = await _verifier.VerifyAsync(entry);

        Assert.False(result.IsValid);
        rsaKey.Dispose();
    }

    [Fact]
    public async Task VerifyAllAsync_MixedEntries_ReturnsOnlyOidc()
    {
        using var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var fingerprint = KeyFingerprint.Compute(signer.PublicKey);
        var audience = "sigil:" + fingerprint.Value;

        var (jwt, rsaKey) = TestJwtBuilder.CreateRs256Token(
            "https://test.example.com", "user", audience);

        var handler = TestJwtBuilder.CreateJwksHandler(rsaKey, "test-kid");
        CreateVerifier(handler);

        var envelope = new SignatureEnvelope
        {
            Subject = new SubjectDescriptor
            {
                Name = "test.txt",
                Digests = new Dictionary<string, string> { ["sha256"] = "abc" }
            },
            Signatures =
            [
                new SignatureEntry
                {
                    KeyId = "sha256:normal-key",
                    Algorithm = "ecdsa-p256",
                    PublicKey = "AAAA",
                    Value = "AAAA",
                    Timestamp = "2025-01-01T00:00:00Z"
                    // No OidcToken
                },
                CreateEntry(signer, jwt)
            ]
        };

        var results = await _verifier!.VerifyAllAsync(envelope);

        // Only the OIDC entry should be in results
        Assert.Single(results);
        Assert.True(results.ContainsKey(fingerprint.Value));
        rsaKey.Dispose();
    }

    [Fact]
    public async Task VerifyAllAsync_NoOidcEntries_ReturnsEmpty()
    {
        CreateVerifier(TestJwtBuilder.CreateJwksHandler(RSA.Create(2048), "k"));

        var envelope = new SignatureEnvelope
        {
            Subject = new SubjectDescriptor
            {
                Name = "test.txt",
                Digests = new Dictionary<string, string> { ["sha256"] = "abc" }
            },
            Signatures =
            [
                new SignatureEntry
                {
                    KeyId = "sha256:key1",
                    Algorithm = "ecdsa-p256",
                    PublicKey = "AAAA",
                    Value = "AAAA",
                    Timestamp = "2025-01-01T00:00:00Z"
                }
            ]
        };

        var results = await _verifier!.VerifyAllAsync(envelope);

        Assert.Empty(results);
    }

    [Fact]
    public async Task VerifyAsync_SigningTimeParsed_PassedToValidator()
    {
        using var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var fingerprint = KeyFingerprint.Compute(signer.PublicKey);
        var audience = "sigil:" + fingerprint.Value;

        // Token expires in 1 hour
        var (jwt, rsaKey) = TestJwtBuilder.CreateRs256Token(
            "https://test.example.com", "user", audience,
            expiration: DateTimeOffset.UtcNow.AddHours(1));

        var handler = TestJwtBuilder.CreateJwksHandler(rsaKey, "test-kid");
        CreateVerifier(handler);

        var entry = CreateEntry(signer, jwt);

        // Validate at signing time (should pass)
        var result = await _verifier!.VerifyAsync(entry, DateTimeOffset.UtcNow);

        Assert.True(result.IsValid);
        rsaKey.Dispose();
    }

    [Fact]
    public async Task VerifyAsync_GenericAudience_Succeeds()
    {
        using var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);

        // JWT has generic audience "sigil" instead of key-specific "sigil:sha256:<fp>"
        var (jwt, rsaKey) = TestJwtBuilder.CreateRs256Token(
            "https://test.example.com", "user@gitlab.com", "sigil");

        var handler = TestJwtBuilder.CreateJwksHandler(rsaKey, "test-kid");
        CreateVerifier(handler);

        var entry = CreateEntry(signer, jwt);
        var result = await _verifier!.VerifyAsync(entry);

        Assert.True(result.IsValid);
        Assert.Equal("https://test.example.com", result.Issuer);
        Assert.Equal("user@gitlab.com", result.Identity);
        rsaKey.Dispose();
    }

    [Fact]
    public async Task VerifyAsync_WrongGenericAudience_Fails()
    {
        using var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);

        // JWT has wrong audience "aws" — not "sigil" and not key-specific
        var (jwt, rsaKey) = TestJwtBuilder.CreateRs256Token(
            "https://test.example.com", "user", "aws");

        var handler = TestJwtBuilder.CreateJwksHandler(rsaKey, "test-kid");
        CreateVerifier(handler);

        var entry = CreateEntry(signer, jwt);
        var result = await _verifier!.VerifyAsync(entry);

        Assert.False(result.IsValid);
        Assert.Contains("audience", result.Error, StringComparison.OrdinalIgnoreCase);
        rsaKey.Dispose();
    }

    private static SignatureEntry CreateEntry(ISigner signer, string jwt)
    {
        var fingerprint = KeyFingerprint.Compute(signer.PublicKey);
        return new SignatureEntry
        {
            KeyId = fingerprint.Value,
            Algorithm = signer.Algorithm.ToCanonicalName(),
            PublicKey = Convert.ToBase64String(signer.PublicKey),
            Value = Convert.ToBase64String(signer.Sign(new byte[] { 1, 2, 3 })),
            Timestamp = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ",
                System.Globalization.CultureInfo.InvariantCulture),
            OidcToken = jwt,
            OidcIssuer = "https://test.example.com",
            OidcIdentity = "user"
        };
    }

    private void CreateVerifier(HttpMessageHandler handler)
    {
        _httpClient = new HttpClient(handler);
        _jwksClient = new JwksClient(_httpClient);
        _jwtValidator = new JwtValidator(_jwksClient);
        _verifier = new OidcVerifier(_jwtValidator);
    }

    public void Dispose()
    {
        _verifier?.Dispose();
        _jwtValidator?.Dispose();
        _jwksClient?.Dispose();
        _httpClient?.Dispose();
    }

    private sealed class FailingHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            throw new HttpRequestException("Connection refused");
        }
    }
}
