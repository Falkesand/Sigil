using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
namespace Sigil.Cli.Tests.Commands;

public class SignPeCommandTests : IDisposable
{
    private readonly string _tempDir;

    public SignPeCommandTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-signpe-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    [Fact]
    public async Task SignPe_NoKey_ReturnsError()
    {
        var pePath = CreateMinimalPe("test.dll");

        var result = await CommandTestHelper.InvokeAsync("sign-pe", pePath);

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("certificate", result.StdErr, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task SignPe_PemKeyRejected()
    {
        var pePath = CreateMinimalPe("test.dll");
        var pemPath = Path.Combine(_tempDir, "key.pem");
        File.WriteAllText(pemPath, "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----");

        var result = await CommandTestHelper.InvokeAsync("sign-pe", pePath, "--key", pemPath);

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("PFX", result.StdErr);
    }

    [Fact]
    public async Task SignPe_MutualExclusion_KeyAndCertStore()
    {
        var pePath = CreateMinimalPe("test.dll");
        var pfxPath = Path.Combine(_tempDir, "test.pfx");
        File.WriteAllBytes(pfxPath, [0]); // Dummy

        var result = await CommandTestHelper.InvokeAsync(
            "sign-pe", pePath, "--key", pfxPath, "--cert-store", "AABBCC");

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("Cannot use both", result.StdErr);
    }

    [Fact]
    public async Task SignPe_ValidPfx_SignsSuccessfully()
    {
        var pePath = CreateMinimalPe("test.dll");
        var pfxPath = CreateTestPfx();
        var outputPath = Path.Combine(_tempDir, "signed.dll");

        var result = await CommandTestHelper.InvokeAsync(
            "sign-pe", pePath,
            "--key", pfxPath,
            "--passphrase", "test",
            "--output", outputPath);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("PE signed", result.StdOut);
        Assert.True(File.Exists(outputPath));
        Assert.True(File.Exists(pePath + ".sig.json"));

        // Verify the signed PE is larger than the original
        var originalSize = new FileInfo(pePath).Length;
        var signedSize = new FileInfo(outputPath).Length;
        Assert.True(signedSize > originalSize);
    }

    [Fact]
    public async Task SignPe_NonPeFile_ReturnsError()
    {
        var notPe = Path.Combine(_tempDir, "notpe.dll");
        File.WriteAllBytes(notPe, [0xFF, 0xFE, 0xFD, 0xFC]);
        var pfxPath = CreateTestPfx();

        var result = await CommandTestHelper.InvokeAsync(
            "sign-pe", notPe,
            "--key", pfxPath,
            "--passphrase", "test");

        Assert.NotEqual(0, result.ExitCode);
    }

    [Fact]
    public async Task SignPe_FileNotFound_ReturnsError()
    {
        var result = await CommandTestHelper.InvokeAsync(
            "sign-pe", Path.Combine(_tempDir, "missing.dll"),
            "--key", "test.pfx");

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("not found", result.StdErr);
    }

    private string CreateMinimalPe(string name)
    {
        var data = CliPeTestHelper.BuildMinimalPe32Plus([0xDE, 0xAD, 0xBE, 0xEF]);
        var path = Path.Combine(_tempDir, name);
        File.WriteAllBytes(path, data);
        return path;
    }

    private string CreateTestPfx()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=SigilPeTest", rsa,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
        using var cert = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddYears(1));
        var pfxBytes = cert.Export(X509ContentType.Pfx, "test");
        var pfxPath = Path.Combine(_tempDir, "test.pfx");
        File.WriteAllBytes(pfxPath, pfxBytes);
        CryptographicOperations.ZeroMemory(pfxBytes);
        return pfxPath;
    }
}
