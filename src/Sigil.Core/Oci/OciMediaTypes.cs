namespace Sigil.Oci;

/// <summary>
/// OCI and Docker media type constants.
/// </summary>
public static class OciMediaTypes
{
    public const string OciManifestV1 = "application/vnd.oci.image.manifest.v1+json";
    public const string OciImageIndex = "application/vnd.oci.image.index.v1+json";
    public const string OciEmptyConfig = "application/vnd.oci.empty.v1+json";
    public const string DockerManifestV2 = "application/vnd.docker.distribution.manifest.v2+json";
    public const string DockerManifestList = "application/vnd.docker.distribution.manifest.list.v2+json";
    public const string SigilSignature = "application/vnd.sigil.signature.v1+json";
}
