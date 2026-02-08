using System.Text;
using Sigil.Crypto;
using Sigil.Keys;
using Sigil.Signing;

namespace Sigil.Integration.Tests;

public class SbomIntegrationTests : IDisposable
{
    private readonly string _tempDir;

    public SbomIntegrationTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-integ-sbom-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    [Fact]
    public void SignVerify_CycloneDx_PreservesMetadata()
    {
        var cycloneDx = """
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {
                "component": {
                    "name": "my-app",
                    "version": "2.0.0",
                    "supplier": { "name": "Acme Corp" }
                }
            },
            "components": [
                { "name": "lib-a", "version": "1.0" },
                { "name": "lib-b", "version": "2.0" }
            ]
        }
        """;

        var artifactPath = Path.Combine(_tempDir, "bom.cdx.json");
        File.WriteAllText(artifactPath, cycloneDx);

        using var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var fp = KeyFingerprint.Compute(signer.PublicKey);

        var envelope = ArtifactSigner.Sign(artifactPath, signer, fp);

        Assert.Equal("application/vnd.cyclonedx+json", envelope.Subject.MediaType);
        Assert.NotNull(envelope.Subject.Metadata);
        Assert.Equal("CycloneDX", envelope.Subject.Metadata["sbom.format"]);
        Assert.Equal("1.5", envelope.Subject.Metadata["sbom.specVersion"]);
        Assert.Equal("my-app", envelope.Subject.Metadata["sbom.name"]);
        Assert.Equal("2.0.0", envelope.Subject.Metadata["sbom.version"]);
        Assert.Equal("Acme Corp", envelope.Subject.Metadata["sbom.supplier"]);
        Assert.Equal("2", envelope.Subject.Metadata["sbom.componentCount"]);

        // Serialize → deserialize → verify (metadata included in signed payload)
        var json = ArtifactSigner.Serialize(envelope);
        var deserialized = ArtifactSigner.Deserialize(json);
        var result = SignatureValidator.Verify(artifactPath, deserialized);

        Assert.True(result.AllSignaturesValid);
        Assert.NotNull(deserialized.Subject.Metadata);
        Assert.Equal("CycloneDX", deserialized.Subject.Metadata["sbom.format"]);
    }

    [Fact]
    public void SignVerify_Spdx_PreservesMetadata()
    {
        var spdx = """
        {
            "spdxVersion": "SPDX-2.3",
            "name": "spdx-doc",
            "documentNamespace": "https://example.com/spdx",
            "creationInfo": {
                "creators": ["Organization: Test Corp"],
                "created": "2024-01-01T00:00:00Z"
            },
            "packages": [
                { "name": "pkg-1", "SPDXID": "SPDXRef-pkg1", "downloadLocation": "https://example.com", "supplier": "Organization: Test Corp" },
                { "name": "pkg-2", "SPDXID": "SPDXRef-pkg2", "downloadLocation": "https://example.com" },
                { "name": "pkg-3", "SPDXID": "SPDXRef-pkg3", "downloadLocation": "https://example.com" }
            ]
        }
        """;

        var artifactPath = Path.Combine(_tempDir, "doc.spdx.json");
        File.WriteAllText(artifactPath, spdx);

        using var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var fp = KeyFingerprint.Compute(signer.PublicKey);

        var envelope = ArtifactSigner.Sign(artifactPath, signer, fp);

        Assert.Equal("application/spdx+json", envelope.Subject.MediaType);
        Assert.NotNull(envelope.Subject.Metadata);
        Assert.Equal("SPDX", envelope.Subject.Metadata["sbom.format"]);
        Assert.Equal("SPDX-2.3", envelope.Subject.Metadata["sbom.specVersion"]);

        var result = SignatureValidator.Verify(artifactPath, envelope);
        Assert.True(result.AllSignaturesValid);
    }

    [Fact]
    public void SignVerify_NonSbom_NoMetadata()
    {
        var artifactPath = Path.Combine(_tempDir, "readme.txt");
        File.WriteAllText(artifactPath, "Just a regular file, not an SBOM.");

        using var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        var fp = KeyFingerprint.Compute(signer.PublicKey);

        var envelope = ArtifactSigner.Sign(artifactPath, signer, fp);

        Assert.Null(envelope.Subject.MediaType);
        Assert.Null(envelope.Subject.Metadata);

        var result = SignatureValidator.Verify(artifactPath, envelope);
        Assert.True(result.AllSignaturesValid);
    }
}
