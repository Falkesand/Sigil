using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Sigil.Keys;
using Sigil.Vault;

namespace Sigil.Core.Tests.Keys;

[SupportedOSPlatform("windows")]
public sealed class CertStoreKeyProviderTests
{
    private static bool IsWindows => OperatingSystem.IsWindows();

    [Fact]
    public void Constructor_NonWindows_ThrowsPlatformNotSupportedException()
    {
        if (IsWindows)
            return; // This test only makes sense on non-Windows platforms

        Assert.Throws<PlatformNotSupportedException>(() => new CertStoreKeyProvider());
    }

    [Fact]
    public async Task GetSignerAsync_CertNotFound_ReturnsKeyNotFound()
    {
        if (!IsWindows) return;

        await using var provider = new CertStoreKeyProvider(StoreLocation.CurrentUser);
        var result = await provider.GetSignerAsync("0000000000000000000000000000000000000000");

        Assert.False(result.IsSuccess);
        Assert.Equal(VaultErrorKind.KeyNotFound, result.ErrorKind);
    }

    [Fact]
    public async Task GetSignerAsync_EmptyThumbprint_ReturnsInvalidKeyReference()
    {
        if (!IsWindows) return;

        await using var provider = new CertStoreKeyProvider(StoreLocation.CurrentUser);
        var result = await provider.GetSignerAsync("");

        Assert.False(result.IsSuccess);
        Assert.Equal(VaultErrorKind.InvalidKeyReference, result.ErrorKind);
    }

    [Fact]
    public async Task GetPublicKeyAsync_CertNotFound_ReturnsKeyNotFound()
    {
        if (!IsWindows) return;

        await using var provider = new CertStoreKeyProvider(StoreLocation.CurrentUser);
        var result = await provider.GetPublicKeyAsync("0000000000000000000000000000000000000000");

        Assert.False(result.IsSuccess);
        Assert.Equal(VaultErrorKind.KeyNotFound, result.ErrorKind);
    }

    [Fact]
    public async Task GetPublicKeyAsync_EmptyThumbprint_ReturnsInvalidKeyReference()
    {
        if (!IsWindows) return;

        await using var provider = new CertStoreKeyProvider(StoreLocation.CurrentUser);
        var result = await provider.GetPublicKeyAsync("");

        Assert.False(result.IsSuccess);
        Assert.Equal(VaultErrorKind.InvalidKeyReference, result.ErrorKind);
    }

    [Fact]
    public async Task GetSignerAsync_InstalledCert_ReturnsSigner()
    {
        if (!IsWindows) return;

        // Install a test cert into the current user store, then remove it after
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=SigilTest", ecdsa, HashAlgorithmName.SHA256);
        using var selfSigned = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5));
        // Re-import with Exportable flag so the private key can be exported from the store
        var pfxBytes = selfSigned.Export(X509ContentType.Pfx, "");
        using var cert = X509CertificateLoader.LoadPkcs12(pfxBytes, "", X509KeyStorageFlags.Exportable);
        var thumbprint = cert.Thumbprint;

        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        store.Add(cert);

        try
        {
            await using var provider = new CertStoreKeyProvider(StoreLocation.CurrentUser);
            var result = await provider.GetSignerAsync(thumbprint);

            Assert.True(result.IsSuccess);
            using var signer = result.Value;
            Assert.NotNull(signer);
            Assert.NotEmpty(signer.PublicKey);

            // Verify we can sign
            var data = System.Text.Encoding.UTF8.GetBytes("cert-store-test");
            var signature = signer.Sign(data);
            Assert.NotEmpty(signature);
        }
        finally
        {
            store.Remove(cert);
        }
    }

    [Fact]
    public async Task GetPublicKeyAsync_InstalledCert_ReturnsSpki()
    {
        if (!IsWindows) return;

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=SigilPubTest", ecdsa, HashAlgorithmName.SHA256);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5));
        var thumbprint = cert.Thumbprint;

        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        store.Add(cert);

        try
        {
            await using var provider = new CertStoreKeyProvider(StoreLocation.CurrentUser);
            var result = await provider.GetPublicKeyAsync(thumbprint);

            Assert.True(result.IsSuccess);
            Assert.NotEmpty(result.Value);

            // Verify it's valid SPKI
            using var verify = ECDsa.Create();
            verify.ImportSubjectPublicKeyInfo(result.Value, out _);
        }
        finally
        {
            store.Remove(cert);
        }
    }

    [Fact]
    public async Task DisposeAsync_CompletesWithoutError()
    {
        if (!IsWindows) return;

        var provider = new CertStoreKeyProvider();
        await provider.DisposeAsync(); // Should not throw
    }

    [Fact]
    public async Task Constructor_DefaultLocation_IsCurrentUser()
    {
        if (!IsWindows) return;

        // Just verify construction succeeds with default
        await using var provider = new CertStoreKeyProvider();
    }

    [Fact]
    public async Task Constructor_LocalMachine_Succeeds()
    {
        if (!IsWindows) return;

        // LocalMachine construction should succeed (even if we can't write to it)
        await using var provider = new CertStoreKeyProvider(StoreLocation.LocalMachine);
    }
}
