using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Sigil.Keyless;

public sealed class JwtValidator : IDisposable
{
    private const int ClockSkewSeconds = 60;

    private readonly JwksClient _jwksClient;
    private readonly bool _ownsClient;

    public JwtValidator(JwksClient jwksClient)
    {
        ArgumentNullException.ThrowIfNull(jwksClient);
        _jwksClient = jwksClient;
        _ownsClient = false;
    }

    public JwtValidator() : this(new JwksClient())
    {
        _ownsClient = true;
    }

    public async Task<KeylessResult<JwtToken>> ValidateAsync(
        string rawToken, string expectedAudience,
        DateTimeOffset? validationTime = null,
        bool allowGenericAudience = false,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rawToken);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedAudience);

        // Step 1: Parse
        var parseResult = JwtParser.Parse(rawToken);
        if (!parseResult.IsSuccess)
        {
            return KeylessResult<JwtToken>.Fail(parseResult.ErrorKind, parseResult.ErrorMessage);
        }

        var token = parseResult.Value;

        // Step 2: Check algorithm
        if (token.Algorithm is not ("RS256" or "ES256"))
        {
            return KeylessResult<JwtToken>.Fail(
                KeylessErrorKind.UnsupportedAlgorithm,
                $"Unsupported JWT algorithm: {token.Algorithm ?? "(none)"}.");
        }

        // Step 3: Check issuer
        if (string.IsNullOrWhiteSpace(token.Issuer))
        {
            return KeylessResult<JwtToken>.Fail(
                KeylessErrorKind.TokenValidationFailed, "JWT missing 'iss' claim.");
        }

        // Step 4: Check audience
        if (!IsAudienceAcceptable(token.Audience, expectedAudience, allowGenericAudience))
        {
            return KeylessResult<JwtToken>.Fail(
                KeylessErrorKind.AudienceMismatch,
                $"Expected audience '{expectedAudience}', got '{token.Audience}'.");
        }

        // Step 5: Check expiration
        var now = validationTime ?? DateTimeOffset.UtcNow;
        if (token.ExpirationUnix is { } exp)
        {
            var expirationTime = DateTimeOffset.FromUnixTimeSeconds(exp);
            if (now > expirationTime.AddSeconds(ClockSkewSeconds))
            {
                return KeylessResult<JwtToken>.Fail(
                    KeylessErrorKind.TokenExpired, "JWT has expired.");
            }
        }

        // Step 6: Fetch JWKS
        var jwksResult = await _jwksClient.FetchJwksAsync(token.Issuer, ct).ConfigureAwait(false);
        if (!jwksResult.IsSuccess)
        {
            return KeylessResult<JwtToken>.Fail(jwksResult.ErrorKind, jwksResult.ErrorMessage);
        }

        // Step 7: Find matching key
        var keys = jwksResult.Value;
        JsonElement? matchingKey = null;

        foreach (var key in keys.EnumerateArray())
        {
            var kidMatch = token.KeyId is null ||
                (key.TryGetProperty("kid", out var kidProp) &&
                 string.Equals(kidProp.GetString(), token.KeyId, StringComparison.Ordinal));

            var algMatch = key.TryGetProperty("alg", out var algProp) &&
                string.Equals(algProp.GetString(), token.Algorithm, StringComparison.Ordinal);

            if (kidMatch && algMatch)
            {
                matchingKey = key;
                break;
            }
        }

        if (matchingKey is null)
        {
            return KeylessResult<JwtToken>.Fail(
                KeylessErrorKind.TokenValidationFailed,
                $"No matching key found in JWKS for kid='{token.KeyId}', alg='{token.Algorithm}'.");
        }

        // Step 8: Verify signature
        var sigResult = VerifySignature(token, matchingKey.Value);
        if (!sigResult.IsSuccess)
        {
            return KeylessResult<JwtToken>.Fail(sigResult.ErrorKind, sigResult.ErrorMessage);
        }

        if (!sigResult.Value)
        {
            return KeylessResult<JwtToken>.Fail(
                KeylessErrorKind.TokenValidationFailed, "JWT signature verification failed.");
        }

        return KeylessResult<JwtToken>.Ok(token);
    }

    internal static KeylessResult<bool> VerifySignature(JwtToken token, JsonElement jwk)
    {
        var signingInputBytes = Encoding.ASCII.GetBytes(token.SigningInput);

        if (!jwk.TryGetProperty("kty", out var ktyProp))
        {
            return KeylessResult<bool>.Fail(
                KeylessErrorKind.TokenValidationFailed, "JWK missing 'kty' property.");
        }

        var kty = ktyProp.GetString();

        if (string.Equals(kty, "RSA", StringComparison.Ordinal) &&
            string.Equals(token.Algorithm, "RS256", StringComparison.Ordinal))
        {
            return VerifyRs256(signingInputBytes, token.SignatureBytes, jwk);
        }

        if (string.Equals(kty, "EC", StringComparison.Ordinal) &&
            string.Equals(token.Algorithm, "ES256", StringComparison.Ordinal))
        {
            return VerifyEs256(signingInputBytes, token.SignatureBytes, jwk);
        }

        return KeylessResult<bool>.Fail(
            KeylessErrorKind.UnsupportedAlgorithm,
            $"Unsupported JWK key type '{kty}' with algorithm '{token.Algorithm}'.");
    }

    private static KeylessResult<bool> VerifyRs256(
        byte[] signingInput, byte[] signature, JsonElement jwk)
    {
        try
        {
            if (!jwk.TryGetProperty("n", out var nProp) || !jwk.TryGetProperty("e", out var eProp))
            {
                return KeylessResult<bool>.Fail(
                    KeylessErrorKind.TokenValidationFailed, "RSA JWK missing 'n' or 'e' parameters.");
            }

            var n = JwtParser.Base64UrlDecode(nProp.GetString()!);
            var e = JwtParser.Base64UrlDecode(eProp.GetString()!);

            var rsaParams = new RSAParameters { Modulus = n, Exponent = e };

            using var rsa = RSA.Create();
            rsa.ImportParameters(rsaParams);

            var isValid = rsa.VerifyData(signingInput, signature,
                HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            return KeylessResult<bool>.Ok(isValid);
        }
        catch (CryptographicException ex)
        {
            return KeylessResult<bool>.Fail(
                KeylessErrorKind.TokenValidationFailed, $"RSA verification error: {ex.Message}");
        }
    }

    private static KeylessResult<bool> VerifyEs256(
        byte[] signingInput, byte[] signature, JsonElement jwk)
    {
        try
        {
            if (!jwk.TryGetProperty("crv", out var crvProp) ||
                !string.Equals(crvProp.GetString(), "P-256", StringComparison.Ordinal))
            {
                return KeylessResult<bool>.Fail(
                    KeylessErrorKind.TokenValidationFailed, "ES256 JWK requires 'crv' = 'P-256'.");
            }

            if (!jwk.TryGetProperty("x", out var xProp) || !jwk.TryGetProperty("y", out var yProp))
            {
                return KeylessResult<bool>.Fail(
                    KeylessErrorKind.TokenValidationFailed, "EC JWK missing 'x' or 'y' parameters.");
            }

            var x = JwtParser.Base64UrlDecode(xProp.GetString()!);
            var y = JwtParser.Base64UrlDecode(yProp.GetString()!);

            var ecParams = new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = x, Y = y }
            };

            using var ecdsa = ECDsa.Create(ecParams);

            // JWT ES256 uses IEEE P1363 format (r || s, each 32 bytes)
            var isValid = ecdsa.VerifyData(signingInput, signature,
                HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

            return KeylessResult<bool>.Ok(isValid);
        }
        catch (CryptographicException ex)
        {
            return KeylessResult<bool>.Fail(
                KeylessErrorKind.TokenValidationFailed, $"ECDSA verification error: {ex.Message}");
        }
    }

    internal const string GenericAudience = "sigil";
    internal const string AudiencePrefix = "sigil:";

    internal static bool IsAudienceAcceptable(
        string? tokenAudience, string expectedAudience, bool allowGeneric)
    {
        if (string.Equals(tokenAudience, expectedAudience, StringComparison.Ordinal))
            return true;

        if (allowGeneric &&
            string.Equals(tokenAudience, GenericAudience, StringComparison.Ordinal) &&
            expectedAudience.StartsWith(AudiencePrefix, StringComparison.Ordinal))
            return true;

        return false;
    }

    public void Dispose()
    {
        if (_ownsClient)
        {
            _jwksClient.Dispose();
        }
    }
}
