using Sigil.Crypto;
using Sigil.Keys;
using Sigil.Signing;

namespace Sigil.Core.Tests.Signing;

public class SbomSigningTests : IDisposable
{
    private readonly string _tempDir;

    public SbomSigningTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-test-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    [Fact]
    public void Sign_CycloneDx_PopulatesMetadataAndMediaType()
    {
        var sbomPath = Path.Combine(_tempDir, "sbom.cdx.json");
        File.WriteAllText(sbomPath, """
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {
                "component": {
                    "name": "my-app",
                    "version": "2.0.0",
                    "supplier": { "name": "Acme Corp" }
                }
            },
            "components": [
                { "name": "lib-a" },
                { "name": "lib-b" }
            ]
        }
        """);

        using var signer = ECDsaP256Signer.Generate();
        var fp = KeyFingerprint.Compute(signer.PublicKey);

        var envelope = ArtifactSigner.Sign(sbomPath, signer, fp);

        Assert.Equal("application/vnd.cyclonedx+json", envelope.Subject.MediaType);
        Assert.NotNull(envelope.Subject.Metadata);
        Assert.Equal("CycloneDX", envelope.Subject.Metadata["sbom.format"]);
        Assert.Equal("1.6", envelope.Subject.Metadata["sbom.specVersion"]);
        Assert.Equal("my-app", envelope.Subject.Metadata["sbom.name"]);
        Assert.Equal("2.0.0", envelope.Subject.Metadata["sbom.version"]);
        Assert.Equal("Acme Corp", envelope.Subject.Metadata["sbom.supplier"]);
        Assert.Equal("2", envelope.Subject.Metadata["sbom.componentCount"]);
    }

    [Fact]
    public void Sign_Spdx_PopulatesMetadataAndMediaType()
    {
        var sbomPath = Path.Combine(_tempDir, "sbom.spdx.json");
        File.WriteAllText(sbomPath, """
        {
            "spdxVersion": "SPDX-2.3",
            "name": "my-spdx-doc",
            "packages": [
                { "name": "main-pkg", "versionInfo": "1.0.0", "supplier": "Organization: Acme" },
                { "name": "dep-pkg" }
            ]
        }
        """);

        using var signer = ECDsaP256Signer.Generate();
        var fp = KeyFingerprint.Compute(signer.PublicKey);

        var envelope = ArtifactSigner.Sign(sbomPath, signer, fp);

        Assert.Equal("application/spdx+json", envelope.Subject.MediaType);
        Assert.NotNull(envelope.Subject.Metadata);
        Assert.Equal("SPDX", envelope.Subject.Metadata["sbom.format"]);
        Assert.Equal("SPDX-2.3", envelope.Subject.Metadata["sbom.specVersion"]);
        Assert.Equal("my-spdx-doc", envelope.Subject.Metadata["sbom.name"]);
    }

    [Fact]
    public void Sign_NonSbomFile_NoMetadataOrMediaType()
    {
        var txtPath = Path.Combine(_tempDir, "readme.txt");
        File.WriteAllText(txtPath, "Just a regular file.");

        using var signer = ECDsaP256Signer.Generate();
        var fp = KeyFingerprint.Compute(signer.PublicKey);

        var envelope = ArtifactSigner.Sign(txtPath, signer, fp);

        Assert.Null(envelope.Subject.MediaType);
        Assert.Null(envelope.Subject.Metadata);
    }

    [Fact]
    public void Sign_CycloneDx_VerifyRoundTrip_WithMetadataInPayload()
    {
        var sbomPath = Path.Combine(_tempDir, "sbom.cdx.json");
        File.WriteAllText(sbomPath, """
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [{ "name": "dep-a" }]
        }
        """);

        using var signer = ECDsaP256Signer.Generate();
        var fp = KeyFingerprint.Compute(signer.PublicKey);

        var envelope = ArtifactSigner.Sign(sbomPath, signer, fp);
        var result = SignatureValidator.Verify(sbomPath, envelope);

        Assert.True(result.AllSignaturesValid);
        Assert.NotNull(envelope.Subject.Metadata);
    }

    [Fact]
    public void Sign_CycloneDx_SerializeDeserialize_PreservesMetadata()
    {
        var sbomPath = Path.Combine(_tempDir, "sbom.cdx.json");
        File.WriteAllText(sbomPath, """
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {
                "component": { "name": "test-app", "version": "1.0.0" }
            },
            "components": [{ "name": "lib-x" }]
        }
        """);

        using var signer = ECDsaP256Signer.Generate();
        var fp = KeyFingerprint.Compute(signer.PublicKey);

        var envelope = ArtifactSigner.Sign(sbomPath, signer, fp);
        var json = ArtifactSigner.Serialize(envelope);
        var deserialized = ArtifactSigner.Deserialize(json);

        Assert.NotNull(deserialized.Subject.Metadata);
        Assert.Equal("CycloneDX", deserialized.Subject.Metadata["sbom.format"]);
        Assert.Equal("test-app", deserialized.Subject.Metadata["sbom.name"]);
        Assert.Equal("application/vnd.cyclonedx+json", deserialized.Subject.MediaType);

        // Verify still succeeds after deserialization
        var result = SignatureValidator.Verify(sbomPath, deserialized);
        Assert.True(result.AllSignaturesValid);
    }
}
