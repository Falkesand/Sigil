using System.Security.Cryptography;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Sigil.Crypto;
using Sigil.Vault;

namespace Sigil.Vault.Pkcs11;

/// <summary>
/// Signs data using a PKCS#11 hardware token. Private key never leaves the device.
/// </summary>
public sealed class Pkcs11Signer : VaultSignerBase
{
    private readonly Pkcs11InteropFactories _factories;
    private readonly ISession? _session;
    private readonly IObjectHandle? _privateKeyHandle;
    private readonly SigningAlgorithm _algorithm;
    private readonly byte[] _publicKey;
    private bool _disposed;

    internal Pkcs11Signer(
        Pkcs11InteropFactories factories,
        ISession? session,
        IObjectHandle? privateKeyHandle,
        SigningAlgorithm algorithm,
        byte[] publicKey)
    {
        _factories = factories;
        _session = session;
        _privateKeyHandle = privateKeyHandle;
        _algorithm = algorithm;
        _publicKey = publicKey;
    }

    public override SigningAlgorithm Algorithm => _algorithm;
    public override byte[] PublicKey => _publicKey;

    public override ValueTask<byte[]> SignAsync(byte[] data, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(data);
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_session is null || _privateKeyHandle is null)
            throw new InvalidOperationException("PKCS#11 session is not available.");

        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            var mechanismType = Pkcs11AlgorithmMap.ToSignMechanism(_algorithm);

            byte[] signature;
            if (_algorithm == SigningAlgorithm.Rsa)
            {
                signature = SignWithPssParams(data, mechanismType);
            }
            else
            {
                using var mechanism = _factories.MechanismFactory.Create(mechanismType);
                signature = _session.Sign(mechanism, _privateKeyHandle, data);
            }

            return new ValueTask<byte[]>(signature);
        }
        catch (Exception ex) when (ex is not OperationCanceledException
                                    and not ArgumentNullException
                                    and not ObjectDisposedException)
        {
            throw new CryptographicException(
                $"PKCS#11 signing failed: {ex.Message}", ex);
        }
    }

    private byte[] SignWithPssParams(byte[] data, CKM mechanismType)
    {
        // RSA-PSS requires mechanism parameters: hash algorithm, MGF, and salt length
        var pssParams = _factories.MechanismParamsFactory.CreateCkRsaPkcsPssParams(
            ConvertToUlong(CKM.CKM_SHA256),
            (ulong)CKG.CKG_MGF1_SHA256,
            32); // salt length = SHA-256 digest length

        using var mechanism = _factories.MechanismFactory.Create(mechanismType, pssParams);
        return _session!.Sign(mechanism, _privateKeyHandle!, data);
    }

    /// <summary>
    /// Converts a CKM enum value to ulong for use in mechanism parameter factories.
    /// </summary>
    private static ulong ConvertToUlong(CKM value) => Convert.ToUInt64(value, System.Globalization.CultureInfo.InvariantCulture);

    public override void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;

        try { _session?.Logout(); }
        catch (Pkcs11Exception) { }
        catch (ObjectDisposedException) { }

        try { _session?.Dispose(); }
        catch (ObjectDisposedException) { }
    }
}
