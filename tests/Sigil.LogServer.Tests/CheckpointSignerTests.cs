using System.Security.Cryptography;
using System.Text;
using Org.Webpki.JsonCanonicalizer;
using Xunit;

namespace Sigil.LogServer.Tests;

public sealed class CheckpointSignerTests
{
    [Fact]
    public void Generate_CreatesValidSignerWithEcdsaP256Key()
    {
        // Act
        using var signer = CheckpointSigner.Generate();

        // Assert
        Assert.NotNull(signer);
        Assert.NotNull(signer.PublicKeySpki);
        Assert.True(signer.PublicKeySpki.Length > 0);
    }

    [Fact]
    public void PublicKeySpki_IsValidSpki_CanImportIntoECDsa()
    {
        // Arrange
        using var signer = CheckpointSigner.Generate();

        // Act
        using var ecdsa = ECDsa.Create();
        var spki = signer.PublicKeySpki;

        // Assert
        var exception = Record.Exception(() => ecdsa.ImportSubjectPublicKeyInfo(spki, out _));
        Assert.Null(exception);
    }

    [Fact]
    public void PublicKeyBase64_IsValidBase64OfPublicKeySpki()
    {
        // Arrange
        using var signer = CheckpointSigner.Generate();

        // Act
        var base64 = signer.PublicKeyBase64;
        var decoded = Convert.FromBase64String(base64);

        // Assert
        Assert.Equal(signer.PublicKeySpki, decoded);
    }

    [Fact]
    public void SignCheckpoint_ProducesBase64DecodableOutput()
    {
        // Arrange
        using var signer = CheckpointSigner.Generate();
        var treeSize = 42L;
        var rootHash = "abc123";
        var timestamp = "2026-02-10T12:00:00Z";

        // Act
        var signed = signer.SignCheckpoint(treeSize, rootHash, timestamp);

        // Assert
        var exception = Record.Exception(() => Convert.FromBase64String(signed));
        Assert.Null(exception);
    }

    [Fact]
    public void SignCheckpoint_OutputContainsJsonPayloadAndSignatureSeparatedByDot()
    {
        // Arrange
        using var signer = CheckpointSigner.Generate();
        var treeSize = 100L;
        var rootHash = "hash123";
        var timestamp = "2026-02-10T12:30:00Z";

        // Act
        var signed = signer.SignCheckpoint(treeSize, rootHash, timestamp);
        var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(signed));

        // Assert
        Assert.Contains(".", decoded);
        var parts = decoded.Split('.');
        Assert.Equal(2, parts.Length);

        // First part should be valid JSON
        var exception = Record.Exception(() => new JsonCanonicalizer(parts[0]));
        Assert.Null(exception);

        // Second part should be valid base64
        var signatureException = Record.Exception(() => Convert.FromBase64String(parts[1]));
        Assert.Null(signatureException);
    }

    [Fact]
    public void SignCheckpoint_IsVerifiable_UsingECDsaSignature()
    {
        // Arrange
        using var signer = CheckpointSigner.Generate();
        var treeSize = 200L;
        var rootHash = "rootHashValue";
        var timestamp = "2026-02-10T13:00:00Z";

        // Act
        var signed = signer.SignCheckpoint(treeSize, rootHash, timestamp);

        // Decode outer base64
        var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(signed));
        var parts = decoded.Split('.');
        var jsonPayload = parts[0];
        var signatureBase64 = parts[1];

        // JCS-canonicalize the payload
        var canonical = new JsonCanonicalizer(jsonPayload).GetEncodedUTF8();

        // Decode signature
        var signature = Convert.FromBase64String(signatureBase64);

        // Import public key and verify
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportSubjectPublicKeyInfo(signer.PublicKeySpki, out _);

        // Assert
        var isValid = ecdsa.VerifyData(canonical, signature, HashAlgorithmName.SHA256);
        Assert.True(isValid);
    }
}
