using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Sigil.Keyless;

namespace Sigil.Core.Tests.Keyless;

internal static class TestJwtBuilder
{
    public static (string Jwt, RSA Key) CreateRs256Token(
        string issuer, string subject, string audience,
        string kid = "test-kid",
        DateTimeOffset? expiration = null,
        DateTimeOffset? issuedAt = null)
    {
        var rsa = RSA.Create(2048);
        var exp = expiration ?? DateTimeOffset.UtcNow.AddHours(1);
        var iat = issuedAt ?? DateTimeOffset.UtcNow;

        var header = JsonSerializer.Serialize(new { alg = "RS256", typ = "JWT", kid });
        var payload = JsonSerializer.Serialize(new
        {
            iss = issuer,
            sub = subject,
            aud = audience,
            exp = exp.ToUnixTimeSeconds(),
            iat = iat.ToUnixTimeSeconds()
        });

        var signingInput = JwtParser.Base64UrlEncode(Encoding.UTF8.GetBytes(header)) +
                           "." +
                           JwtParser.Base64UrlEncode(Encoding.UTF8.GetBytes(payload));

        var signatureBytes = rsa.SignData(
            Encoding.ASCII.GetBytes(signingInput),
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var jwt = signingInput + "." + JwtParser.Base64UrlEncode(signatureBytes);
        return (jwt, rsa);
    }

    public static (string Jwt, ECDsa Key) CreateEs256Token(
        string issuer, string subject, string audience,
        string kid = "test-kid-ec",
        DateTimeOffset? expiration = null,
        DateTimeOffset? issuedAt = null)
    {
        var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var exp = expiration ?? DateTimeOffset.UtcNow.AddHours(1);
        var iat = issuedAt ?? DateTimeOffset.UtcNow;

        var header = JsonSerializer.Serialize(new { alg = "ES256", typ = "JWT", kid });
        var payload = JsonSerializer.Serialize(new
        {
            iss = issuer,
            sub = subject,
            aud = audience,
            exp = exp.ToUnixTimeSeconds(),
            iat = iat.ToUnixTimeSeconds()
        });

        var signingInput = JwtParser.Base64UrlEncode(Encoding.UTF8.GetBytes(header)) +
                           "." +
                           JwtParser.Base64UrlEncode(Encoding.UTF8.GetBytes(payload));

        var signatureBytes = ecdsa.SignData(
            Encoding.ASCII.GetBytes(signingInput),
            HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        var jwt = signingInput + "." + JwtParser.Base64UrlEncode(signatureBytes);
        return (jwt, ecdsa);
    }

    public static HttpMessageHandler CreateJwksHandler(RSA publicKey, string kid)
    {
        var parameters = publicKey.ExportParameters(false);
        var jwk = new
        {
            kty = "RSA",
            kid,
            alg = "RS256",
            use = "sig",
            n = JwtParser.Base64UrlEncode(parameters.Modulus!),
            e = JwtParser.Base64UrlEncode(parameters.Exponent!)
        };

        return CreateHandler(jwk);
    }

    public static HttpMessageHandler CreateJwksHandler(ECDsa publicKey, string kid)
    {
        var parameters = publicKey.ExportParameters(false);
        var jwk = new
        {
            kty = "EC",
            kid,
            alg = "ES256",
            use = "sig",
            crv = "P-256",
            x = JwtParser.Base64UrlEncode(parameters.Q.X!),
            y = JwtParser.Base64UrlEncode(parameters.Q.Y!)
        };

        return CreateHandler(jwk);
    }

    private static MockJwksHttpHandler CreateHandler(object jwk)
    {
        var jwksJson = JsonSerializer.Serialize(new { keys = new[] { jwk } });
        var configJson = JsonSerializer.Serialize(new
        {
            issuer = "https://test.example.com",
            jwks_uri = "https://test.example.com/.well-known/jwks.json"
        });

        return new MockJwksHttpHandler(configJson, jwksJson);
    }

    internal sealed class MockJwksHttpHandler : HttpMessageHandler
    {
        private readonly string _configJson;
        private readonly string _jwksJson;

        public MockJwksHttpHandler(string configJson, string jwksJson)
        {
            _configJson = configJson;
            _jwksJson = jwksJson;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var response = new HttpResponseMessage(System.Net.HttpStatusCode.OK);

            if (request.RequestUri?.PathAndQuery.Contains("openid-configuration",
                    StringComparison.OrdinalIgnoreCase) == true)
            {
                response.Content = new StringContent(_configJson, Encoding.UTF8, "application/json");
            }
            else
            {
                response.Content = new StringContent(_jwksJson, Encoding.UTF8, "application/json");
            }

            return Task.FromResult(response);
        }
    }
}
