using System.Globalization;
using Sigil.Keys;
using Sigil.Signing;
using Sigil.Timestamping;

namespace Sigil.Keyless;

public sealed class OidcVerifier : IDisposable
{
    private readonly JwtValidator _jwtValidator;
    private readonly bool _ownsValidator;

    public OidcVerifier(JwtValidator jwtValidator)
    {
        ArgumentNullException.ThrowIfNull(jwtValidator);
        _jwtValidator = jwtValidator;
        _ownsValidator = false;
    }

    public OidcVerifier() : this(new JwtValidator())
    {
        _ownsValidator = true;
    }

    public async Task<OidcVerificationInfo> VerifyAsync(
        SignatureEntry entry, DateTimeOffset? signingTime = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(entry);

        if (string.IsNullOrWhiteSpace(entry.OidcToken))
        {
            return new OidcVerificationInfo
            {
                IsValid = false,
                Error = "No OIDC token present in signature entry."
            };
        }

        // Compute expected audience from the entry's public key
        byte[] publicKeyBytes;
        try
        {
            publicKeyBytes = Convert.FromBase64String(entry.PublicKey);
        }
        catch (FormatException)
        {
            return new OidcVerificationInfo
            {
                IsValid = false,
                Error = "Invalid base64 public key in signature entry."
            };
        }

        var fingerprint = KeyFingerprint.Compute(publicKeyBytes);
        var expectedAudience = "sigil:" + fingerprint.Value;

        var result = await _jwtValidator.ValidateAsync(
            entry.OidcToken, expectedAudience, signingTime, ct).ConfigureAwait(false);

        if (!result.IsSuccess)
        {
            return new OidcVerificationInfo
            {
                IsValid = false,
                Error = result.ErrorMessage
            };
        }

        return new OidcVerificationInfo
        {
            IsValid = true,
            Issuer = result.Value.Issuer,
            Identity = result.Value.Subject
        };
    }

    public async Task<IReadOnlyDictionary<string, OidcVerificationInfo>> VerifyAllAsync(
        SignatureEnvelope envelope, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        return await VerifyEntriesAsync(envelope.Signatures, ct).ConfigureAwait(false);
    }

    public async Task<IReadOnlyDictionary<string, OidcVerificationInfo>> VerifyEntriesAsync(
        IReadOnlyList<SignatureEntry> entries, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(entries);

        var results = new Dictionary<string, OidcVerificationInfo>();

        foreach (var entry in entries)
        {
            if (string.IsNullOrWhiteSpace(entry.OidcToken))
                continue;

            DateTimeOffset? signingTime = null;
            if (DateTimeOffset.TryParse(entry.Timestamp, CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal, out var ts))
            {
                signingTime = ts;
            }

            var info = await VerifyAsync(entry, signingTime, ct).ConfigureAwait(false);
            results[entry.KeyId] = info;
        }

        return results;
    }

    public void Dispose()
    {
        if (_ownsValidator)
        {
            _jwtValidator.Dispose();
        }
    }
}
