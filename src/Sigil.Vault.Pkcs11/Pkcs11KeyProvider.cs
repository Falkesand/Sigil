using System.Security.Cryptography;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Sigil.Crypto;
using Sigil.Vault;

namespace Sigil.Vault.Pkcs11;

/// <summary>
/// PKCS#11 hardware token key provider. Supports HSMs, YubiKeys, and smart cards.
/// </summary>
/// <remarks>
/// PKCS#11 operations are inherently synchronous (native library calls).
/// The async interface methods wrap synchronous results in Task.FromResult.
/// PIN values are stored as strings because <see cref="ISession.Login(CKU, string)"/>
/// requires string input. For production use, prefer PKCS11_PIN environment variable
/// over embedding pin-value in URIs (which may leak via logs or command history).
/// </remarks>
public sealed class Pkcs11KeyProvider : IKeyProvider
{
    private readonly string _libraryPath;
    private readonly string? _pin;
    private readonly Pkcs11InteropFactories _factories;
    private IPkcs11Library? _library;
    private bool _disposed;

    private Pkcs11KeyProvider(string libraryPath, string? pin)
    {
        _libraryPath = libraryPath;
        _pin = pin;
        _factories = new Pkcs11InteropFactories();
    }

    /// <summary>
    /// Creates a PKCS#11 key provider with an explicit library path and optional PIN.
    /// </summary>
    public static VaultResult<IKeyProvider> Create(string libraryPath, string? pin)
    {
        if (string.IsNullOrEmpty(libraryPath))
            return VaultResult<IKeyProvider>.Fail(
                VaultErrorKind.ConfigurationError,
                "PKCS#11 library path must not be null or empty.");

        return VaultResult<IKeyProvider>.Ok(new Pkcs11KeyProvider(libraryPath, pin));
    }

    /// <summary>
    /// Creates a PKCS#11 key provider from environment variables.
    /// Requires PKCS11_LIBRARY; optionally reads PKCS11_PIN.
    /// </summary>
    public static VaultResult<IKeyProvider> CreateFromEnvironment()
    {
        var libraryPath = Environment.GetEnvironmentVariable("PKCS11_LIBRARY");
        if (string.IsNullOrEmpty(libraryPath))
            return VaultResult<IKeyProvider>.Fail(
                VaultErrorKind.ConfigurationError,
                "PKCS11_LIBRARY environment variable is not set. Set it to the path of your PKCS#11 library.");

        var pin = Environment.GetEnvironmentVariable("PKCS11_PIN");
        return VaultResult<IKeyProvider>.Ok(new Pkcs11KeyProvider(libraryPath, pin));
    }

    public Task<VaultResult<ISigner>> GetSignerAsync(string keyReference, CancellationToken ct = default)
    {
        return Task.FromResult(GetSigner(keyReference));
    }

    public Task<VaultResult<byte[]>> GetPublicKeyAsync(string keyReference, CancellationToken ct = default)
    {
        return Task.FromResult(GetPublicKey(keyReference));
    }

    private VaultResult<ISigner> GetSigner(string keyReference)
    {
        if (string.IsNullOrEmpty(keyReference))
            return VaultResult<ISigner>.Fail(VaultErrorKind.InvalidKeyReference, "Key reference must not be empty.");

        var uriResult = ParseKeyReference(keyReference);
        if (!uriResult.IsSuccess)
            return VaultResult<ISigner>.Fail(uriResult.ErrorKind, uriResult.ErrorMessage);

        var components = uriResult.Value;

        try
        {
            var library = EnsureLibrary();
            var pin = ResolvePinValue(components);

            var slot = FindSlot(library, components);
            if (slot is null)
                return VaultResult<ISigner>.Fail(VaultErrorKind.KeyNotFound,
                    $"No PKCS#11 slot found matching token='{components.Token}'.");

            var session = slot.OpenSession(SessionType.ReadOnly);
            try
            {
                if (pin is not null)
                    session.Login(CKU.CKU_USER, pin);

                var privateKey = FindPrivateKey(session, components);
                if (privateKey is null)
                {
                    session.Dispose();
                    return VaultResult<ISigner>.Fail(VaultErrorKind.KeyNotFound,
                        $"No private key found matching object='{components.ObjectLabel}'.");
                }

                var algorithmResult = DetectAlgorithm(session, privateKey);
                if (!algorithmResult.IsSuccess)
                {
                    session.Dispose();
                    return VaultResult<ISigner>.Fail(algorithmResult.ErrorKind, algorithmResult.ErrorMessage);
                }

                var spki = ExtractPublicKeySpki(session, components, algorithmResult.Value);
                if (spki is null)
                {
                    session.Dispose();
                    return VaultResult<ISigner>.Fail(VaultErrorKind.KeyNotFound,
                        "Could not extract public key from PKCS#11 token.");
                }

                // Session ownership transfers to the signer
                var signer = new Pkcs11Signer(_factories, session, privateKey, algorithmResult.Value, spki);
                return VaultResult<ISigner>.Ok(signer);
            }
            catch
            {
                session.Dispose();
                throw;
            }
        }
        catch (Pkcs11Exception ex)
        {
            return MapPkcs11Exception<ISigner>(ex);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return VaultResult<ISigner>.Fail(VaultErrorKind.NetworkError,
                $"PKCS#11 operation failed: {ex.Message}");
        }
    }

    private VaultResult<byte[]> GetPublicKey(string keyReference)
    {
        if (string.IsNullOrEmpty(keyReference))
            return VaultResult<byte[]>.Fail(VaultErrorKind.InvalidKeyReference, "Key reference must not be empty.");

        var uriResult = ParseKeyReference(keyReference);
        if (!uriResult.IsSuccess)
            return VaultResult<byte[]>.Fail(uriResult.ErrorKind, uriResult.ErrorMessage);

        var components = uriResult.Value;

        try
        {
            var library = EnsureLibrary();
            var pin = ResolvePinValue(components);

            var slot = FindSlot(library, components);
            if (slot is null)
                return VaultResult<byte[]>.Fail(VaultErrorKind.KeyNotFound,
                    $"No PKCS#11 slot found matching token='{components.Token}'.");

            using var session = slot.OpenSession(SessionType.ReadOnly);
            if (pin is not null)
                session.Login(CKU.CKU_USER, pin);

            // Try to find a public key object first
            var publicKeyHandle = FindPublicKey(session, components);
            if (publicKeyHandle is not null)
            {
                var algorithm = DetectAlgorithm(session, publicKeyHandle);
                if (algorithm.IsSuccess)
                {
                    var spki = ExtractPublicKeySpki(session, components, algorithm.Value);
                    if (spki is not null)
                        return VaultResult<byte[]>.Ok(spki);
                }
            }

            // Fall back to extracting from private key
            var privateKey = FindPrivateKey(session, components);
            if (privateKey is null)
                return VaultResult<byte[]>.Fail(VaultErrorKind.KeyNotFound,
                    $"No key found matching object='{components.ObjectLabel}'.");

            var algResult = DetectAlgorithm(session, privateKey);
            if (!algResult.IsSuccess)
                return VaultResult<byte[]>.Fail(algResult.ErrorKind, algResult.ErrorMessage);

            var spkiBytes = ExtractPublicKeySpki(session, components, algResult.Value);
            if (spkiBytes is null)
                return VaultResult<byte[]>.Fail(VaultErrorKind.KeyNotFound,
                    "Could not extract public key from PKCS#11 token.");

            return VaultResult<byte[]>.Ok(spkiBytes);
        }
        catch (Pkcs11Exception ex)
        {
            return MapPkcs11Exception<byte[]>(ex);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return VaultResult<byte[]>.Fail(VaultErrorKind.NetworkError,
                $"PKCS#11 operation failed: {ex.Message}");
        }
    }

    public ValueTask DisposeAsync()
    {
        if (_disposed)
            return ValueTask.CompletedTask;
        _disposed = true;

        try { _library?.Dispose(); }
        catch (Pkcs11Exception) { }

        _library = null;
        return ValueTask.CompletedTask;
    }

    private IPkcs11Library EnsureLibrary()
    {
        return _library ??= _factories.Pkcs11LibraryFactory.LoadPkcs11Library(
            _factories, _libraryPath, AppType.MultiThreaded);
    }

    private string? ResolvePinValue(Pkcs11UriComponents components)
    {
        // Priority: URI pin-value > constructor pin > PKCS11_PIN env var
        return components.PinValue
            ?? _pin
            ?? Environment.GetEnvironmentVariable("PKCS11_PIN");
    }

    private static VaultResult<Pkcs11UriComponents> ParseKeyReference(string keyReference)
    {
        // If it looks like a PKCS#11 URI or legacy path, parse it
        if (keyReference.StartsWith("pkcs11:", StringComparison.OrdinalIgnoreCase)
            || keyReference.Contains(';'))
        {
            return Pkcs11UriParser.Parse(keyReference);
        }

        // Reject non-pkcs11 URIs (http://, https://, etc.)
        if (keyReference.Contains("://"))
            return VaultResult<Pkcs11UriComponents>.Fail(VaultErrorKind.InvalidKeyReference,
                $"Invalid PKCS#11 key reference: '{keyReference}'. Use a pkcs11: URI or a plain key label.");

        // Plain key label — treat as object name
        return VaultResult<Pkcs11UriComponents>.Ok(new Pkcs11UriComponents { ObjectLabel = keyReference });
    }

    private static ISlot? FindSlot(IPkcs11Library library, Pkcs11UriComponents components)
    {
        var slots = library.GetSlotList(SlotsType.WithTokenPresent);

        if (components.SlotId.HasValue)
            return slots.FirstOrDefault(s => s.SlotId == components.SlotId.Value);

        if (components.Token is not null)
        {
            var trimmedToken = components.Token.Trim();
            return slots.FirstOrDefault(s =>
            {
                var tokenInfo = s.GetTokenInfo();
                return tokenInfo.Label.Trim() == trimmedToken;
            });
        }

        // No filter — return first available slot
        return slots.FirstOrDefault();
    }

    private IObjectHandle? FindPrivateKey(ISession session, Pkcs11UriComponents components)
    {
        var searchTemplate = new List<IObjectAttribute>
        {
            _factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY)
        };

        if (components.ObjectLabel is not null)
            searchTemplate.Add(_factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, components.ObjectLabel));

        if (components.Id is not null)
            searchTemplate.Add(_factories.ObjectAttributeFactory.Create(CKA.CKA_ID, components.Id));

        var keys = session.FindAllObjects(searchTemplate);
        return keys.Count > 0 ? keys[0] : null;
    }

    private IObjectHandle? FindPublicKey(ISession session, Pkcs11UriComponents components)
    {
        var searchTemplate = new List<IObjectAttribute>
        {
            _factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY)
        };

        if (components.ObjectLabel is not null)
            searchTemplate.Add(_factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, components.ObjectLabel));

        if (components.Id is not null)
            searchTemplate.Add(_factories.ObjectAttributeFactory.Create(CKA.CKA_ID, components.Id));

        var keys = session.FindAllObjects(searchTemplate);
        return keys.Count > 0 ? keys[0] : null;
    }

    private static VaultResult<SigningAlgorithm> DetectAlgorithm(ISession session, IObjectHandle keyHandle)
    {
        var attrs = session.GetAttributeValue(keyHandle, new List<CKA> { CKA.CKA_KEY_TYPE });
        var keyType = (CKK)attrs[0].GetValueAsUlong();

        byte[]? ecParams = null;
        if (keyType == CKK.CKK_EC)
        {
            var ecAttrs = session.GetAttributeValue(keyHandle, new List<CKA> { CKA.CKA_EC_PARAMS });
            ecParams = ecAttrs[0].GetValueAsByteArray();
        }

        var algorithm = Pkcs11AlgorithmMap.FromPkcs11KeyType(keyType, ecParams);
        if (algorithm is null)
            return VaultResult<SigningAlgorithm>.Fail(VaultErrorKind.UnsupportedAlgorithm,
                $"Unsupported PKCS#11 key type: {keyType}");

        return VaultResult<SigningAlgorithm>.Ok(algorithm.Value);
    }

    private byte[]? ExtractPublicKeySpki(ISession session, Pkcs11UriComponents components, SigningAlgorithm algorithm)
    {
        // Find the matching public key object
        var publicKeyHandle = FindPublicKey(session, components);

        if (algorithm == SigningAlgorithm.Rsa)
            return ExtractRsaSpki(session, publicKeyHandle ?? FindPrivateKeyForPublicExtraction(session, components));

        // EC key
        return ExtractEcSpki(session, publicKeyHandle ?? FindPrivateKeyForPublicExtraction(session, components), algorithm);
    }

    private IObjectHandle? FindPrivateKeyForPublicExtraction(ISession session, Pkcs11UriComponents components)
    {
        // Some tokens store EC point on the private key object too
        return FindPrivateKey(session, components);
    }

    private static byte[]? ExtractRsaSpki(ISession session, IObjectHandle? keyHandle)
    {
        if (keyHandle is null)
            return null;

        try
        {
            var attrs = session.GetAttributeValue(keyHandle, new List<CKA>
            {
                CKA.CKA_MODULUS,
                CKA.CKA_PUBLIC_EXPONENT
            });

            var modulus = attrs[0].GetValueAsByteArray();
            var exponent = attrs[1].GetValueAsByteArray();

            if (modulus is null || exponent is null)
                return null;

            using var rsa = RSA.Create(new RSAParameters
            {
                Modulus = modulus,
                Exponent = exponent
            });

            return rsa.ExportSubjectPublicKeyInfo();
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return null;
        }
    }

    private static byte[]? ExtractEcSpki(ISession session, IObjectHandle? keyHandle, SigningAlgorithm algorithm)
    {
        if (keyHandle is null)
            return null;

        try
        {
            var attrs = session.GetAttributeValue(keyHandle, new List<CKA> { CKA.CKA_EC_POINT });
            var ecPoint = attrs[0].GetValueAsByteArray();

            if (ecPoint is null || ecPoint.Length == 0)
                return null;

            // EC point may be wrapped in a DER OCTET STRING; unwrap if so
            var pointBytes = UnwrapEcPoint(ecPoint);

            // First byte must be 0x04 (uncompressed format)
            if (pointBytes.Length == 0 || pointBytes[0] != 0x04)
                return null;

            var coordLen = (pointBytes.Length - 1) / 2;
            var x = pointBytes[1..(1 + coordLen)];
            var y = pointBytes[(1 + coordLen)..];

            var curve = algorithm switch
            {
                SigningAlgorithm.ECDsaP256 => ECCurve.NamedCurves.nistP256,
                SigningAlgorithm.ECDsaP384 => ECCurve.NamedCurves.nistP384,
                _ => throw new NotSupportedException($"Unsupported EC algorithm: {algorithm}")
            };

            using var ecdsa = ECDsa.Create(new ECParameters
            {
                Curve = curve,
                Q = new ECPoint { X = x, Y = y }
            });

            return ecdsa.ExportSubjectPublicKeyInfo();
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return null;
        }
    }

    /// <summary>
    /// PKCS#11 tokens may wrap the EC point in a DER OCTET STRING (tag 0x04, length, data).
    /// This method unwraps it if present, returning the raw uncompressed point.
    /// </summary>
    internal static byte[] UnwrapEcPoint(byte[] ecPoint)
    {
        if (ecPoint.Length < 3)
            return ecPoint;

        // Check if first byte is DER OCTET STRING tag (0x04)
        // and the second byte is a valid length for the remaining data
        if (ecPoint[0] == 0x04)
        {
            // Could be DER-wrapped or raw uncompressed point (both start with 0x04)
            // DER: 0x04 <length> <point-data-starting-with-0x04>
            // Raw: 0x04 <X> <Y>
            //
            // Distinguish: if ecPoint[1] is the correct length for remaining bytes
            // AND ecPoint[2] is 0x04, it's DER-wrapped
            int derLen = ecPoint[1];
            if (derLen == ecPoint.Length - 2 && ecPoint.Length > 2 && ecPoint[2] == 0x04)
            {
                return ecPoint[2..];
            }
        }

        return ecPoint;
    }

    private static VaultResult<T> MapPkcs11Exception<T>(Pkcs11Exception ex)
    {
        var errorKind = ex.RV switch
        {
            CKR.CKR_PIN_INCORRECT or CKR.CKR_PIN_LOCKED or CKR.CKR_PIN_EXPIRED
                => VaultErrorKind.AuthenticationFailed,
            CKR.CKR_TOKEN_NOT_PRESENT or CKR.CKR_SLOT_ID_INVALID
                => VaultErrorKind.KeyNotFound,
            CKR.CKR_USER_NOT_LOGGED_IN
                => VaultErrorKind.AccessDenied,
            CKR.CKR_MECHANISM_INVALID or CKR.CKR_KEY_TYPE_INCONSISTENT
                => VaultErrorKind.UnsupportedAlgorithm,
            _ => VaultErrorKind.NetworkError
        };

        return VaultResult<T>.Fail(errorKind, $"PKCS#11 error ({ex.RV}): {ex.Message}");
    }
}
