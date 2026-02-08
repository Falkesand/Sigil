using Net.Pkcs11Interop.Common;
using Sigil.Crypto;

namespace Sigil.Vault.Pkcs11;

/// <summary>
/// Maps between PKCS#11 key types/mechanisms and Sigil's <see cref="SigningAlgorithm"/>.
/// </summary>
public static class Pkcs11AlgorithmMap
{
    /// <summary>DER-encoded OID for NIST P-256 curve (1.2.840.10045.3.1.7).</summary>
    public static ReadOnlySpan<byte> EcParamsP256 => [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

    /// <summary>DER-encoded OID for NIST P-384 curve (1.3.132.0.34).</summary>
    public static ReadOnlySpan<byte> EcParamsP384 => [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22];

    /// <summary>
    /// Detects the signing algorithm from a PKCS#11 key type and optional EC parameters.
    /// </summary>
    /// <param name="keyType">PKCS#11 key type (CKK value).</param>
    /// <param name="ecParams">DER-encoded EC parameters OID for EC keys, null for non-EC.</param>
    /// <returns>The detected algorithm, or null if unsupported.</returns>
    public static SigningAlgorithm? FromPkcs11KeyType(CKK keyType, byte[]? ecParams)
    {
        if (keyType == CKK.CKK_EC)
        {
            if (ecParams is null)
                return null;

            if (ecParams.AsSpan().SequenceEqual(EcParamsP256))
                return SigningAlgorithm.ECDsaP256;

            if (ecParams.AsSpan().SequenceEqual(EcParamsP384))
                return SigningAlgorithm.ECDsaP384;

            return null;
        }

        if (keyType == CKK.CKK_RSA)
            return SigningAlgorithm.Rsa;

        return null;
    }

    /// <summary>
    /// Maps a Sigil signing algorithm to the PKCS#11 mechanism for combined hash-and-sign.
    /// </summary>
    public static CKM ToSignMechanism(SigningAlgorithm algorithm) => algorithm switch
    {
        SigningAlgorithm.ECDsaP256 => CKM.CKM_ECDSA_SHA256,
        SigningAlgorithm.ECDsaP384 => CKM.CKM_ECDSA_SHA384,
        SigningAlgorithm.Rsa => CKM.CKM_SHA256_RSA_PKCS_PSS,
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm,
            $"PKCS#11 does not support algorithm: {algorithm}")
    };
}
