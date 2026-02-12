using Sigil.Pe;

namespace Sigil.Core.Tests.Pe;

public class AuthenticodeVerifierTests : IDisposable
{
    private readonly System.Security.Cryptography.X509Certificates.X509Certificate2 _cert;

    public AuthenticodeVerifierTests()
    {
        _cert = PeCertHelper.CreateSelfSignedRsaCert();
    }

    public void Dispose()
    {
        _cert.Dispose();
    }

    [Fact]
    public void Verify_SignedPe_IsValid()
    {
        var peBytes = PeTestHelper.BuildMinimalPe32Plus([0xDE, 0xAD, 0xBE, 0xEF]);
        var signResult = AuthenticodeSigner.Sign(peBytes, _cert);
        Assert.True(signResult.IsSuccess);

        var verifyResult = AuthenticodeVerifier.Verify(signResult.Value.SignedPeBytes);

        Assert.True(verifyResult.IsSuccess);
        Assert.True(verifyResult.Value.IsValid);
        Assert.Equal("SHA-256", verifyResult.Value.DigestAlgorithm);
        Assert.Contains("SigilTest", verifyResult.Value.SubjectName);
    }

    [Fact]
    public void Verify_UnsignedPe_ReturnsNoSignature()
    {
        var peBytes = PeTestHelper.BuildMinimalPe32Plus();

        var verifyResult = AuthenticodeVerifier.Verify(peBytes);

        Assert.True(verifyResult.IsSuccess);
        Assert.False(verifyResult.Value.IsValid);
        Assert.Contains("No Authenticode signature", verifyResult.Value.Error);
    }

    [Fact]
    public void Verify_TamperedPe_Fails()
    {
        var peBytes = PeTestHelper.BuildMinimalPe32Plus([0x01, 0x02, 0x03, 0x04]);
        var signResult = AuthenticodeSigner.Sign(peBytes, _cert);
        Assert.True(signResult.IsSuccess);

        var signedPe = signResult.Value.SignedPeBytes;
        // Tamper with section content
        var parsedPe = PeFile.Parse(signedPe).Value;
        if (parsedPe.Sections.Count > 0 && parsedPe.Sections[0].SizeOfRawData > 0)
        {
            signedPe[(int)parsedPe.Sections[0].PointerToRawData] ^= 0xFF;
        }

        var verifyResult = AuthenticodeVerifier.Verify(signedPe);

        Assert.True(verifyResult.IsSuccess);
        Assert.False(verifyResult.Value.IsValid);
        Assert.NotNull(verifyResult.Value.Error);
    }

    [Fact]
    public void Verify_ExtractsSubjectAndThumbprint()
    {
        var peBytes = PeTestHelper.BuildMinimalPe32Plus();
        var signResult = AuthenticodeSigner.Sign(peBytes, _cert);
        Assert.True(signResult.IsSuccess);

        var verifyResult = AuthenticodeVerifier.Verify(signResult.Value.SignedPeBytes);

        Assert.True(verifyResult.IsSuccess);
        Assert.True(verifyResult.Value.IsValid);
        Assert.NotEmpty(verifyResult.Value.SubjectName);
        Assert.NotEmpty(verifyResult.Value.IssuerName);
        Assert.NotEmpty(verifyResult.Value.Thumbprint);
    }

    [Fact]
    public void Verify_NotPeFile_ReturnsFail()
    {
        var notPe = new byte[] { 0xFF, 0xFE, 0xFD, 0xFC };

        var result = AuthenticodeVerifier.Verify(notPe);

        Assert.False(result.IsSuccess);
    }

    [Fact]
    public void Verify_SignAndVerify_Roundtrip_Pe32()
    {
        var peBytes = PeTestHelper.BuildMinimalPe32([0xAA, 0xBB, 0xCC]);
        var signResult = AuthenticodeSigner.Sign(peBytes, _cert);
        Assert.True(signResult.IsSuccess);

        var verifyResult = AuthenticodeVerifier.Verify(signResult.Value.SignedPeBytes);

        Assert.True(verifyResult.IsSuccess);
        Assert.True(verifyResult.Value.IsValid);
    }

    [Fact]
    public void Verify_SignAndVerify_Roundtrip_Pe32Plus()
    {
        var peBytes = PeTestHelper.BuildMinimalPe32Plus([0x11, 0x22, 0x33, 0x44, 0x55]);
        var signResult = AuthenticodeSigner.Sign(peBytes, _cert);
        Assert.True(signResult.IsSuccess);

        var verifyResult = AuthenticodeVerifier.Verify(signResult.Value.SignedPeBytes);

        Assert.True(verifyResult.IsSuccess);
        Assert.True(verifyResult.Value.IsValid);
    }

    [Fact]
    public void Verify_EcdsaCert_Roundtrip()
    {
        using var ecCert = PeCertHelper.CreateSelfSignedEcdsaCert();
        var peBytes = PeTestHelper.BuildMinimalPe32Plus();
        var signResult = AuthenticodeSigner.Sign(peBytes, ecCert);
        Assert.True(signResult.IsSuccess);

        var verifyResult = AuthenticodeVerifier.Verify(signResult.Value.SignedPeBytes);

        Assert.True(verifyResult.IsSuccess);
        Assert.True(verifyResult.Value.IsValid);
    }

    [Fact]
    public void Verify_CorruptedCertTable_ReturnsFail()
    {
        var peBytes = PeTestHelper.BuildMinimalPe32Plus();
        var signResult = AuthenticodeSigner.Sign(peBytes, _cert);
        Assert.True(signResult.IsSuccess);

        var signedPe = signResult.Value.SignedPeBytes;
        var pe = PeFile.Parse(signedPe).Value;

        // Corrupt the WIN_CERTIFICATE header (revision field)
        signedPe[(int)pe.CertTableFileOffset + 4] = 0xFF;
        signedPe[(int)pe.CertTableFileOffset + 5] = 0xFF;

        var verifyResult = AuthenticodeVerifier.Verify(signedPe);

        // Should fail because of unsupported revision
        Assert.False(verifyResult.IsSuccess);
        Assert.Contains("revision", verifyResult.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }
}
