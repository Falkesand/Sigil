using Sigil.Pe;

namespace Sigil.Core.Tests.Pe;

public class AuthenticodeTimestamperTests
{
    [Fact]
    public async Task ApplyTimestampAsync_InvalidUri_ReturnsFail()
    {
        // Create a valid PKCS#7 blob by signing a PE
        using var cert = PeCertHelper.CreateSelfSignedRsaCert();
        var peBytes = PeTestHelper.BuildMinimalPe32Plus();
        var signResult = AuthenticodeSigner.Sign(peBytes, cert);
        Assert.True(signResult.IsSuccess);

        // Extract PKCS#7 from the signed PE
        var parsedPe = PeFile.Parse(signResult.Value.SignedPeBytes).Value;
        int pkcs7Start = (int)parsedPe.CertTableFileOffset + 8;
        uint dwLength = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(
            signResult.Value.SignedPeBytes.AsSpan((int)parsedPe.CertTableFileOffset));
        int pkcs7Length = (int)dwLength - 8;
        var pkcs7Bytes = signResult.Value.SignedPeBytes.AsSpan(pkcs7Start, pkcs7Length).ToArray();

        // Use an unreachable URI — should fail with network error
        var result = await AuthenticodeTimestamper.ApplyTimestampAsync(
            pkcs7Bytes,
            new Uri("https://127.0.0.1:1/timestamp"),
            CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.Equal(AuthenticodeErrorKind.TimestampFailed, result.ErrorKind);
    }

    [Fact]
    public async Task ApplyTimestampAsync_EmptyPkcs7_ReturnsFail()
    {
        var result = await AuthenticodeTimestamper.ApplyTimestampAsync(
            [0x30, 0x00], // Minimal but invalid DER
            new Uri("https://example.com/timestamp"),
            CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.Equal(AuthenticodeErrorKind.TimestampFailed, result.ErrorKind);
    }
}
