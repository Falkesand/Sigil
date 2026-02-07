using Sigil.Crypto;
using Sigil.Keys;

namespace Sigil.Core.Tests.Keys;

public class KeyStoreTests : IDisposable
{
    private readonly string _tempDir;
    private readonly KeyStore _store;

    public KeyStoreTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-test-" + Guid.NewGuid().ToString("N")[..8]);
        _store = new KeyStore(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    [Fact]
    public void GenerateKey_CreatesFilesOnDisk()
    {
        var fp = _store.GenerateKey();

        Assert.True(_store.KeyExists(fp));

        var keys = _store.ListKeys();
        Assert.Single(keys);
        Assert.Equal(fp.Value, keys[0].Fingerprint);
        Assert.True(keys[0].HasPrivateKey);
    }

    [Fact]
    public void GenerateKey_WithLabel_StoresLabel()
    {
        var fp = _store.GenerateKey(label: "my-key");

        var keys = _store.ListKeys();
        Assert.Single(keys);
        Assert.Equal("my-key", keys[0].Label);
    }

    [Fact]
    public void GenerateKey_WithPassphrase_EncryptsPrivateKey()
    {
        var fp = _store.GenerateKey(passphrase: "secret");

        // Should be loadable with correct passphrase
        using var signer = _store.LoadSigner(fp, "secret");
        Assert.NotNull(signer);

        // Should fail without passphrase
        Assert.Throws<InvalidOperationException>(() => _store.LoadSigner(fp));
    }

    [Fact]
    public void LoadSigner_RoundTrip_ProducesValidSignatures()
    {
        var fp = _store.GenerateKey();
        using var signer = _store.LoadSigner(fp);

        var data = new byte[] { 1, 2, 3, 4, 5 };
        var signature = signer.Sign(data);

        var verifier = _store.LoadVerifier(fp);
        Assert.True(verifier.Verify(data, signature));
    }

    [Fact]
    public void ImportPublicKey_CanVerifyButNotSign()
    {
        // Generate key in one store
        using var originalSigner = ECDsaP256Signer.Generate();
        var pem = originalSigner.ExportPublicKeyPem();

        // Import into our test store
        var fp = _store.ImportPublicKey(pem, "imported");

        var keys = _store.ListKeys();
        Assert.Single(keys);
        Assert.False(keys[0].HasPrivateKey);
        Assert.Equal("imported", keys[0].Label);

        // Can load verifier
        var verifier = _store.LoadVerifier(fp);
        Assert.NotNull(verifier);

        // Cannot load signer
        Assert.Throws<FileNotFoundException>(() => _store.LoadSigner(fp));
    }

    [Fact]
    public void ImportPublicKey_Idempotent()
    {
        using var signer = ECDsaP256Signer.Generate();
        var pem = signer.ExportPublicKeyPem();

        var fp1 = _store.ImportPublicKey(pem);
        var fp2 = _store.ImportPublicKey(pem);

        Assert.Equal(fp1, fp2);
        Assert.Single(_store.ListKeys());
    }

    [Fact]
    public void ExportPublicKeyPem_ReturnsValidPem()
    {
        var fp = _store.GenerateKey();
        var pem = _store.ExportPublicKeyPem(fp);

        Assert.Contains("BEGIN PUBLIC KEY", pem);
        Assert.Contains("END PUBLIC KEY", pem);
    }

    [Fact]
    public void ListKeys_Empty_ReturnsEmptyList()
    {
        var keys = _store.ListKeys();
        Assert.Empty(keys);
    }

    [Fact]
    public void LoadSigner_NonexistentKey_Throws()
    {
        var fp = KeyFingerprint.Parse("sha256:0000000000000000000000000000000000000000000000000000000000000000");
        Assert.Throws<FileNotFoundException>(() => _store.LoadSigner(fp));
    }
}
