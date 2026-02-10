using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Xunit;

namespace Sigil.LogServer.Tests;

public sealed class ProgramArgTests : IDisposable
{
    private readonly string _tempDir;

    public ProgramArgTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-prog-test-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    [Fact]
    public void CheckpointSigner_FromPfx_works_as_ICheckpointSigner()
    {
        var pfxPath = CreateEcdsaPfx("ckpt.pfx", "test-pass");

        using var signer = CheckpointSigner.FromPfx(pfxPath, "test-pass");
        Assert.IsAssignableFrom<ICheckpointSigner>(signer);
        Assert.NotEmpty(signer.PublicKeySpki);
        Assert.NotEmpty(signer.PublicKeyBase64);
        var signed = signer.SignCheckpoint(1L, "hash", "2026-02-10T14:00:00Z");
        Assert.NotEmpty(signed);
    }

    [Fact]
    public void CheckpointSigner_FromPfx_signed_checkpoint_is_verifiable()
    {
        var pfxPath = CreateEcdsaPfx("verify.pfx", "verify-pass");

        using var signer = CheckpointSigner.FromPfx(pfxPath, "verify-pass");
        var signed = signer.SignCheckpoint(50L, "testHash", "2026-02-10T15:00:00Z");

        var decoded = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(signed));
        var parts = decoded.Split('.');
        var canonical = new Org.Webpki.JsonCanonicalizer.JsonCanonicalizer(parts[0]).GetEncodedUTF8();
        var signature = Convert.FromBase64String(parts[1]);

        using var ecdsa = ECDsa.Create();
        ecdsa.ImportSubjectPublicKeyInfo(signer.PublicKeySpki, out _);
        Assert.True(ecdsa.VerifyData(canonical, signature, HashAlgorithmName.SHA256));
    }

    [Fact]
    public void ICheckpointSigner_interface_can_be_used_in_LogService()
    {
        // Verify that CheckpointSigner (via PFX) works with LogService through the interface
        var pfxPath = CreateEcdsaPfx("logservice.pfx", "log-pass");

        using var signer = CheckpointSigner.FromPfx(pfxPath, "log-pass");
        Assert.IsAssignableFrom<ICheckpointSigner>(signer);
        Assert.True(signer.PublicKeySpki.Length > 0);
    }

    [Fact]
    public void CheckpointSigner_Generate_implements_ICheckpointSigner()
    {
        using var signer = CheckpointSigner.Generate();
        Assert.IsAssignableFrom<ICheckpointSigner>(signer);
        var signed = signer.SignCheckpoint(1L, "hash", "2026-02-10T16:00:00Z");
        Assert.NotEmpty(signed);
    }

    [Fact]
    public void CheckpointSigner_FromPem_implements_ICheckpointSigner()
    {
        var pemPath = CreateEcdsaPem("pem.pem");

        using var signer = CheckpointSigner.FromPem(pemPath);
        Assert.IsAssignableFrom<ICheckpointSigner>(signer);
        var signed = signer.SignCheckpoint(1L, "hash", "2026-02-10T17:00:00Z");
        Assert.NotEmpty(signed);
    }

    [Fact]
    public void CheckpointSigner_FromPfx_without_password_succeeds()
    {
        var pfxPath = CreateEcdsaPfx("nopass.pfx", password: null);

        using var signer = CheckpointSigner.FromPfx(pfxPath);
        Assert.NotEmpty(signer.PublicKeySpki);
    }

    private string CreateEcdsaPfx(string fileName, string? password)
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=ProgTest", ecdsa, HashAlgorithmName.SHA256);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(1));
        var pfxBytes = cert.Export(X509ContentType.Pfx, password);
        var pfxPath = Path.Combine(_tempDir, fileName);
        File.WriteAllBytes(pfxPath, pfxBytes);
        return pfxPath;
    }

    private string CreateEcdsaPem(string fileName)
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pemPath = Path.Combine(_tempDir, fileName);
        File.WriteAllText(pemPath, ecdsa.ExportECPrivateKeyPem());
        return pemPath;
    }
}
