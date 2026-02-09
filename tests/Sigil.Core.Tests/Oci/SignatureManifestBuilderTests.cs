using System.Text.Json;
using Sigil.Oci;

namespace Sigil.Core.Tests.Oci;

public class SignatureManifestBuilderTests
{
    private readonly OciDescriptor _subject = new()
    {
        MediaType = OciMediaTypes.OciManifestV1,
        Digest = "sha256:abc123",
        Size = 9999
    };

    [Fact]
    public void ArtifactType_is_sigil_signature()
    {
        var manifest = SignatureManifestBuilder.Build(_subject, [1, 2, 3]);

        Assert.Equal(OciMediaTypes.SigilSignature, manifest.ArtifactType);
    }

    [Fact]
    public void Config_is_empty_oci_descriptor()
    {
        var manifest = SignatureManifestBuilder.Build(_subject, [1, 2, 3]);

        Assert.Equal(OciMediaTypes.OciEmptyConfig, manifest.Config.MediaType);
        Assert.Equal(2, manifest.Config.Size);
        Assert.Equal(SignatureManifestBuilder.EmptyConfigDigest, manifest.Config.Digest);
    }

    [Fact]
    public void Layer_descriptor_matches_envelope()
    {
        var envelope = System.Text.Encoding.UTF8.GetBytes("""{"version":"1.0"}""");

        var manifest = SignatureManifestBuilder.Build(_subject, envelope);

        Assert.Single(manifest.Layers);
        Assert.Equal(OciMediaTypes.SigilSignature, manifest.Layers[0].MediaType);
        Assert.Equal(envelope.Length, manifest.Layers[0].Size);
        Assert.StartsWith("sha256:", manifest.Layers[0].Digest);
    }

    [Fact]
    public void Subject_matches_signed_image()
    {
        var manifest = SignatureManifestBuilder.Build(_subject, [1, 2, 3]);

        Assert.NotNull(manifest.Subject);
        Assert.Equal(_subject.Digest, manifest.Subject.Digest);
        Assert.Equal(_subject.Size, manifest.Subject.Size);
        Assert.Equal(_subject.MediaType, manifest.Subject.MediaType);
    }

    [Fact]
    public void MediaType_is_oci_manifest_v1()
    {
        var manifest = SignatureManifestBuilder.Build(_subject, [1, 2, 3]);

        Assert.Equal(OciMediaTypes.OciManifestV1, manifest.MediaType);
    }

    [Fact]
    public void Serialized_manifest_is_valid_json()
    {
        var manifest = SignatureManifestBuilder.Build(_subject, [1, 2, 3]);

        var json = manifest.Serialize();
        var doc = JsonDocument.Parse(json);

        Assert.Equal(2, doc.RootElement.GetProperty("schemaVersion").GetInt32());
        Assert.True(doc.RootElement.TryGetProperty("subject", out _));
        Assert.True(doc.RootElement.TryGetProperty("artifactType", out _));
    }
}
