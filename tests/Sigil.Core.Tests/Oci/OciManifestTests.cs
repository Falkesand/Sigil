using System.Text.Json;
using Sigil.Oci;

namespace Sigil.Core.Tests.Oci;

public class OciManifestTests
{
    private const string OciManifestJson = """
        {
          "schemaVersion": 2,
          "mediaType": "application/vnd.oci.image.manifest.v1+json",
          "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": "sha256:aaa111",
            "size": 1234
          },
          "layers": [
            {
              "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
              "digest": "sha256:bbb222",
              "size": 5678
            }
          ]
        }
        """;

    private const string DockerManifestJson = """
        {
          "schemaVersion": 2,
          "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
          "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "digest": "sha256:ccc333",
            "size": 100
          },
          "layers": [
            {
              "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
              "digest": "sha256:ddd444",
              "size": 200
            }
          ]
        }
        """;

    private const string OciIndexJson = """
        {
          "schemaVersion": 2,
          "mediaType": "application/vnd.oci.image.index.v1+json",
          "config": {
            "mediaType": "application/vnd.oci.empty.v1+json",
            "digest": "sha256:eee555",
            "size": 2
          },
          "layers": []
        }
        """;

    [Fact]
    public void Deserialize_OciManifestV1()
    {
        var result = OciManifest.Deserialize(OciManifestJson);

        Assert.True(result.IsSuccess);
        Assert.Equal(2, result.Value.SchemaVersion);
        Assert.Equal(OciMediaTypes.OciManifestV1, result.Value.MediaType);
        Assert.Equal("sha256:aaa111", result.Value.Config.Digest);
        Assert.Single(result.Value.Layers);
        Assert.Equal("sha256:bbb222", result.Value.Layers[0].Digest);
    }

    [Fact]
    public void Deserialize_DockerManifestV2()
    {
        var result = OciManifest.Deserialize(DockerManifestJson);

        Assert.True(result.IsSuccess);
        Assert.Equal(OciMediaTypes.DockerManifestV2, result.Value.MediaType);
        Assert.Equal("sha256:ccc333", result.Value.Config.Digest);
    }

    [Fact]
    public void Deserialize_OciImageIndex()
    {
        var result = OciManifest.Deserialize(OciIndexJson);

        Assert.True(result.IsSuccess);
        Assert.Equal(OciMediaTypes.OciImageIndex, result.Value.MediaType);
        Assert.Empty(result.Value.Layers);
    }

    [Fact]
    public void RoundTrip_preserves_fields()
    {
        var original = OciManifest.Deserialize(OciManifestJson);
        Assert.True(original.IsSuccess);

        var json = original.Value.Serialize();
        var roundTripped = OciManifest.Deserialize(json);

        Assert.True(roundTripped.IsSuccess);
        Assert.Equal(original.Value.SchemaVersion, roundTripped.Value.SchemaVersion);
        Assert.Equal(original.Value.Config.Digest, roundTripped.Value.Config.Digest);
        Assert.Equal(original.Value.Layers.Count, roundTripped.Value.Layers.Count);
    }

    [Fact]
    public void Subject_field_parsed()
    {
        var json = """
            {
              "schemaVersion": 2,
              "mediaType": "application/vnd.oci.image.manifest.v1+json",
              "artifactType": "application/vnd.sigil.signature.v1+json",
              "config": {
                "mediaType": "application/vnd.oci.empty.v1+json",
                "digest": "sha256:44136fa355b311bfa706c3dba8b08a9b3bb45c4c5d86a99e340f0a2b9df3ac36",
                "size": 2
              },
              "layers": [],
              "subject": {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:abc123",
                "size": 9999
              }
            }
            """;

        var result = OciManifest.Deserialize(json);

        Assert.True(result.IsSuccess);
        Assert.NotNull(result.Value.Subject);
        Assert.Equal("sha256:abc123", result.Value.Subject.Digest);
        Assert.Equal(9999, result.Value.Subject.Size);
    }

    [Fact]
    public void Missing_optional_fields_handled()
    {
        var json = """
            {
              "schemaVersion": 2,
              "config": {
                "mediaType": "application/vnd.oci.empty.v1+json",
                "digest": "sha256:000",
                "size": 2
              },
              "layers": []
            }
            """;

        var result = OciManifest.Deserialize(json);

        Assert.True(result.IsSuccess);
        Assert.Null(result.Value.MediaType);
        Assert.Null(result.Value.ArtifactType);
        Assert.Null(result.Value.Subject);
        Assert.Null(result.Value.Annotations);
    }

    [Fact]
    public void ArtifactType_preserved()
    {
        var json = """
            {
              "schemaVersion": 2,
              "artifactType": "application/vnd.sigil.signature.v1+json",
              "config": {
                "mediaType": "application/vnd.oci.empty.v1+json",
                "digest": "sha256:000",
                "size": 2
              },
              "layers": []
            }
            """;

        var result = OciManifest.Deserialize(json);

        Assert.True(result.IsSuccess);
        Assert.Equal(OciMediaTypes.SigilSignature, result.Value.ArtifactType);
    }

    [Fact]
    public void Malformed_json_returns_error()
    {
        var result = OciManifest.Deserialize("not valid json {{{");

        Assert.False(result.IsSuccess);
        Assert.Equal(OciErrorKind.InvalidManifest, result.ErrorKind);
    }
}
