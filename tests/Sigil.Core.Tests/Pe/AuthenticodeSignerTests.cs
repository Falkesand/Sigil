using System.Buffers.Binary;
using Sigil.Pe;

namespace Sigil.Core.Tests.Pe;

public class AuthenticodeSignerTests : IDisposable
{
    private readonly X509Certificate2Holder _certHolder;

    public AuthenticodeSignerTests()
    {
        _certHolder = new X509Certificate2Holder(PeCertHelper.CreateSelfSignedRsaCert());
    }

    public void Dispose()
    {
        _certHolder.Dispose();
    }

    [Fact]
    public void Sign_Pe32_Succeeds()
    {
        var peBytes = PeTestHelper.BuildMinimalPe32([0xDE, 0xAD]);

        var result = AuthenticodeSigner.Sign(peBytes, _certHolder.Certificate);

        Assert.True(result.IsSuccess);
        Assert.NotNull(result.Value.SignedPeBytes);
        Assert.True(result.Value.SignedPeBytes.Length > peBytes.Length);
    }

    [Fact]
    public void Sign_Pe32Plus_Succeeds()
    {
        var peBytes = PeTestHelper.BuildMinimalPe32Plus([0xCA, 0xFE]);

        var result = AuthenticodeSigner.Sign(peBytes, _certHolder.Certificate);

        Assert.True(result.IsSuccess);
        Assert.True(result.Value.SignedPeBytes.Length > peBytes.Length);
    }

    [Fact]
    public void Sign_UpdatesChecksum()
    {
        var peBytes = PeTestHelper.BuildMinimalPe32Plus();

        var result = AuthenticodeSigner.Sign(peBytes, _certHolder.Certificate);

        Assert.True(result.IsSuccess);
        var signedPe = result.Value.SignedPeBytes;
        var parseResult = PeFile.Parse(signedPe);
        Assert.True(parseResult.IsSuccess);

        uint storedChecksum = BinaryPrimitives.ReadUInt32LittleEndian(
            signedPe.AsSpan(parseResult.Value.CheckSumOffset));
        Assert.NotEqual(0u, storedChecksum);
    }

    [Fact]
    public void Sign_UpdatesCertTableDirectory()
    {
        var peBytes = PeTestHelper.BuildMinimalPe32Plus();

        var result = AuthenticodeSigner.Sign(peBytes, _certHolder.Certificate);

        Assert.True(result.IsSuccess);
        var signedPe = result.Value.SignedPeBytes;
        var parseResult = PeFile.Parse(signedPe);
        Assert.True(parseResult.IsSuccess);

        var pe = parseResult.Value;
        Assert.True(pe.CertTableFileOffset > 0);
        Assert.True(pe.CertTableSize > 0);
    }

    [Fact]
    public void Sign_ProducesDetachedEnvelope()
    {
        var peBytes = PeTestHelper.BuildMinimalPe32Plus();

        var result = AuthenticodeSigner.Sign(peBytes, _certHolder.Certificate);

        Assert.True(result.IsSuccess);
        var envelope = result.Value.Envelope;
        Assert.NotNull(envelope);
        Assert.Equal("1.0", envelope.Version);
        Assert.Single(envelope.Signatures);
        Assert.True(envelope.Subject.Digests.ContainsKey("sha256"));
        Assert.True(envelope.Subject.Digests.ContainsKey("sha512"));
    }

    [Fact]
    public void Sign_WithLabel_LabelInEnvelope()
    {
        var peBytes = PeTestHelper.BuildMinimalPe32();

        var result = AuthenticodeSigner.Sign(peBytes, _certHolder.Certificate, label: "test-label");

        Assert.True(result.IsSuccess);
        Assert.Equal("test-label", result.Value.Envelope.Signatures[0].Label);
    }

    [Fact]
    public void Sign_WithEcdsaCert_Succeeds()
    {
        using var ecCert = PeCertHelper.CreateSelfSignedEcdsaCert();
        var peBytes = PeTestHelper.BuildMinimalPe32Plus();

        var result = AuthenticodeSigner.Sign(peBytes, ecCert);

        Assert.True(result.IsSuccess);
        Assert.True(result.Value.SignedPeBytes.Length > peBytes.Length);
    }

    [Fact]
    public void Sign_InvalidPe_ReturnsFail()
    {
        var notPe = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF };

        var result = AuthenticodeSigner.Sign(notPe, _certHolder.Certificate);

        Assert.False(result.IsSuccess);
    }

    /// <summary>
    /// Helper to keep the certificate alive for the test lifetime.
    /// </summary>
    private sealed class X509Certificate2Holder : IDisposable
    {
        public System.Security.Cryptography.X509Certificates.X509Certificate2 Certificate { get; }

        public X509Certificate2Holder(System.Security.Cryptography.X509Certificates.X509Certificate2 cert)
        {
            Certificate = cert;
        }

        public void Dispose() => Certificate.Dispose();
    }
}
