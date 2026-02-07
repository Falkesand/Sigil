using System.Security.Cryptography;

namespace Sigil.Crypto;

/// <summary>
/// Computes digests for artifacts and key fingerprints.
/// </summary>
public static class HashAlgorithms
{
    public static byte[] Sha256(byte[] data)
    {
        return SHA256.HashData(data);
    }

    public static byte[] Sha256(Stream stream)
    {
        return SHA256.HashData(stream);
    }

    public static byte[] Sha512(byte[] data)
    {
        return SHA512.HashData(data);
    }

    public static byte[] Sha512(Stream stream)
    {
        return SHA512.HashData(stream);
    }

    public static string Sha256Hex(byte[] data)
    {
        return Convert.ToHexStringLower(Sha256(data));
    }

    public static string Sha512Hex(byte[] data)
    {
        return Convert.ToHexStringLower(Sha512(data));
    }

    public static (string sha256, string sha512) ComputeDigests(Stream stream)
    {
        stream.Position = 0;
        var sha256 = Convert.ToHexStringLower(SHA256.HashData(stream));
        stream.Position = 0;
        var sha512 = Convert.ToHexStringLower(SHA512.HashData(stream));
        return (sha256, sha512);
    }

    public static (string sha256, string sha512) ComputeDigests(byte[] data)
    {
        return (Sha256Hex(data), Sha512Hex(data));
    }
}
