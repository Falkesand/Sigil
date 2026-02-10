using Sigil.Crypto;
using Sigil.Keys;

namespace Sigil.Keyless;

public sealed class KeylessSigner : IDisposable
{
    public ISigner Signer { get; }
    public string OidcToken { get; }
    public string OidcIssuer { get; }
    public string OidcIdentity { get; }

    public KeylessSigner(ISigner ephemeralSigner, string oidcToken, string oidcIssuer, string oidcIdentity)
    {
        ArgumentNullException.ThrowIfNull(ephemeralSigner);
        ArgumentException.ThrowIfNullOrWhiteSpace(oidcToken);
        ArgumentException.ThrowIfNullOrWhiteSpace(oidcIssuer);
        ArgumentException.ThrowIfNullOrWhiteSpace(oidcIdentity);

        Signer = ephemeralSigner;
        OidcToken = oidcToken;
        OidcIssuer = oidcIssuer;
        OidcIdentity = oidcIdentity;
    }

    public static async Task<KeylessResult<KeylessSigner>> CreateAsync(
        IOidcTokenProvider tokenProvider,
        SigningAlgorithm algorithm = SigningAlgorithm.ECDsaP256,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(tokenProvider);

        var signer = SignerFactory.Generate(algorithm);
        var fingerprint = KeyFingerprint.Compute(signer.PublicKey);
        var audience = "sigil:" + fingerprint.Value;

        var tokenResult = await tokenProvider.AcquireTokenAsync(audience, ct).ConfigureAwait(false);
        if (!tokenResult.IsSuccess)
        {
            signer.Dispose();
            return KeylessResult<KeylessSigner>.Fail(tokenResult.ErrorKind, tokenResult.ErrorMessage);
        }

        var parseResult = JwtParser.Parse(tokenResult.Value);
        if (!parseResult.IsSuccess)
        {
            signer.Dispose();
            return KeylessResult<KeylessSigner>.Fail(parseResult.ErrorKind, parseResult.ErrorMessage);
        }

        var token = parseResult.Value;
        var issuer = token.Issuer;
        var subject = token.Subject;

        if (string.IsNullOrWhiteSpace(issuer) || string.IsNullOrWhiteSpace(subject))
        {
            signer.Dispose();
            return KeylessResult<KeylessSigner>.Fail(
                KeylessErrorKind.TokenParsingFailed,
                "OIDC token missing 'iss' or 'sub' claim.");
        }

        var keylessSigner = new KeylessSigner(signer, tokenResult.Value, issuer, subject);
        return KeylessResult<KeylessSigner>.Ok(keylessSigner);
    }

    public void Dispose()
    {
        Signer.Dispose();
    }
}
