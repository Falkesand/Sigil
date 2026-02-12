using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Sigil.Pe;
namespace Sigil.Cli.Tests.Commands;

public class VerifyPeCommandTests : IDisposable
{
    private readonly string _tempDir;

    public VerifyPeCommandTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-verifype-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    [Fact]
    public async Task VerifyPe_UnsignedPe_ReportsFailed()
    {
        var pePath = CreateMinimalPe("unsigned.dll");

        var result = await CommandTestHelper.InvokeAsync("verify-pe", pePath);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("No Authenticode signature", result.StdOut);
    }

    [Fact]
    public async Task VerifyPe_SignedPe_ReportsVerified()
    {
        var pePath = CreateMinimalPe("test.dll");
        var pfxPath = CreateTestPfx();
        var signedPath = Path.Combine(_tempDir, "signed.dll");

        // Sign first
        await CommandTestHelper.InvokeAsync(
            "sign-pe", pePath,
            "--key", pfxPath,
            "--passphrase", "test",
            "--output", signedPath);

        // Copy .sig.json to match signed PE path
        var srcSigPath = pePath + ".sig.json";
        var dstSigPath = signedPath + ".sig.json";
        if (File.Exists(srcSigPath))
            File.Copy(srcSigPath, dstSigPath, true);

        var result = await CommandTestHelper.InvokeAsync("verify-pe", signedPath);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("VERIFIED", result.StdOut);
    }

    [Fact]
    public async Task VerifyPe_TamperedPe_ReportsFailed()
    {
        var pePath = CreateMinimalPe("test.dll");
        var pfxPath = CreateTestPfx();
        var signedPath = Path.Combine(_tempDir, "signed.dll");

        await CommandTestHelper.InvokeAsync(
            "sign-pe", pePath,
            "--key", pfxPath,
            "--passphrase", "test",
            "--output", signedPath);

        // Tamper with signed PE
        var signedBytes = File.ReadAllBytes(signedPath);
        var peFile = PeFile.Parse(signedBytes).Value;
        if (peFile.Sections.Count > 0 && peFile.Sections[0].SizeOfRawData > 0)
        {
            signedBytes[(int)peFile.Sections[0].PointerToRawData] ^= 0xFF;
            File.WriteAllBytes(signedPath, signedBytes);
        }

        var result = await CommandTestHelper.InvokeAsync("verify-pe", signedPath);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("FAILED", result.StdOut);
    }

    [Fact]
    public async Task VerifyPe_FileNotFound_ReportsError()
    {
        var result = await CommandTestHelper.InvokeAsync(
            "verify-pe", Path.Combine(_tempDir, "missing.dll"));

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("not found", result.StdErr);
    }

    [Fact]
    public async Task VerifyPe_WithSigJson_ReportsBoth()
    {
        var pePath = CreateMinimalPe("test.dll");
        var pfxPath = CreateTestPfx();
        var signedPath = Path.Combine(_tempDir, "signed.dll");

        await CommandTestHelper.InvokeAsync(
            "sign-pe", pePath,
            "--key", pfxPath,
            "--passphrase", "test",
            "--output", signedPath);

        // Copy .sig.json
        var srcSigPath = pePath + ".sig.json";
        var dstSigPath = signedPath + ".sig.json";
        if (File.Exists(srcSigPath))
            File.Copy(srcSigPath, dstSigPath, true);

        var result = await CommandTestHelper.InvokeAsync("verify-pe", signedPath);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Authenticode", result.StdOut);
        Assert.Contains("Sigil envelope", result.StdOut);
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
