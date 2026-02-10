using Sigil.Vault.Pkcs11;

namespace Sigil.Vault.Pkcs11.Tests;

public class Pkcs11KeyProviderInternalTests
{
    [Fact]
    public void UnwrapEcPoint_RawUncompressedP256_ReturnsUnchanged()
    {
        // Raw uncompressed P-256 point: 04 + 32 bytes X + 32 bytes Y = 65 bytes
        var raw = new byte[65];
        raw[0] = 0x04;
        for (int i = 1; i < 65; i++) raw[i] = (byte)i;

        var result = Pkcs11KeyProvider.UnwrapEcPoint(raw);

        Assert.Equal(raw, result);
    }

    [Fact]
    public void UnwrapEcPoint_DerWrappedP256_UnwrapsCorrectly()
    {
        // DER OCTET STRING wrapping: 04 41 04 <32 bytes X> <32 bytes Y>
        var raw = new byte[65];
        raw[0] = 0x04;
        for (int i = 1; i < 65; i++) raw[i] = (byte)i;

        var wrapped = new byte[67];
        wrapped[0] = 0x04; // DER OCTET STRING tag
        wrapped[1] = 65;   // length of inner data
        Array.Copy(raw, 0, wrapped, 2, 65);

        var result = Pkcs11KeyProvider.UnwrapEcPoint(wrapped);

        Assert.Equal(raw, result);
    }

    [Fact]
    public void UnwrapEcPoint_DerWrappedP384_UnwrapsCorrectly()
    {
        // DER OCTET STRING wrapping for P-384: 04 61 04 <48 bytes X> <48 bytes Y>
        var raw = new byte[97]; // 1 + 48 + 48
        raw[0] = 0x04;
        for (int i = 1; i < 97; i++) raw[i] = (byte)(i % 256);

        var wrapped = new byte[99]; // 2 + 97
        wrapped[0] = 0x04;
        wrapped[1] = 97;
        Array.Copy(raw, 0, wrapped, 2, 97);

        var result = Pkcs11KeyProvider.UnwrapEcPoint(wrapped);

        Assert.Equal(raw, result);
    }

    [Fact]
    public void UnwrapEcPoint_DerWrappedP521_LongFormLength_UnwrapsCorrectly()
    {
        // P-521 uses long-form DER length encoding:
        // 0x04 0x81 0x85 0x04 <132 bytes> = 136 total
        var raw = new byte[133]; // 1 + 66 + 66
        raw[0] = 0x04;
        for (int i = 1; i < 133; i++) raw[i] = (byte)(i % 256);

        var wrapped = new byte[136]; // 3-byte header + 133 bytes data
        wrapped[0] = 0x04;  // DER OCTET STRING tag
        wrapped[1] = 0x81;  // long-form: 1 subsequent length byte
        wrapped[2] = 133;   // actual length
        Array.Copy(raw, 0, wrapped, 3, 133);

        var result = Pkcs11KeyProvider.UnwrapEcPoint(wrapped);

        Assert.Equal(raw, result);
    }

    [Fact]
    public void UnwrapEcPoint_ShortInput_ReturnsUnchanged()
    {
        var input = new byte[] { 0x04, 0x01 };

        var result = Pkcs11KeyProvider.UnwrapEcPoint(input);

        Assert.Equal(input, result);
    }

    [Fact]
    public void UnwrapEcPoint_EmptyInput_ReturnsUnchanged()
    {
        var input = Array.Empty<byte>();

        var result = Pkcs11KeyProvider.UnwrapEcPoint(input);

        Assert.Equal(input, result);
    }

    [Fact]
    public void UnwrapEcPoint_NonPointData_ReturnsUnchanged()
    {
        // Not starting with 0x04
        var input = new byte[] { 0x03, 0x20, 0x01, 0x02, 0x03 };

        var result = Pkcs11KeyProvider.UnwrapEcPoint(input);

        Assert.Equal(input, result);
    }
}
