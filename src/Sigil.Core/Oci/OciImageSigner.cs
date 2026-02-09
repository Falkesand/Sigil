using System.Text;
using Sigil.Crypto;
using Sigil.Keys;
using Sigil.Signing;
using Sigil.Timestamping;

namespace Sigil.Oci;

/// <summary>
/// Orchestrates signing an OCI image: HEAD manifest → GET manifest → sign → upload → push.
/// </summary>
public static class OciImageSigner
{
    /// <summary>
    /// Signs an OCI image and pushes the signature as a referrer artifact.
    /// </summary>
    public static async Task<OciResult<OciSignResult>> SignAsync(
        OciRegistryClient registryClient,
        ImageReference imageRef,
        ISigner signer,
        string? label = null,
        Uri? tsaUrl = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(registryClient);
        ArgumentNullException.ThrowIfNull(imageRef);
        ArgumentNullException.ThrowIfNull(signer);

        // 1. HEAD manifest to get descriptor
        var headResult = await registryClient.HeadManifestAsync(
            imageRef.RepositoryPath, imageRef.ManifestReference, ct).ConfigureAwait(false);
        if (!headResult.IsSuccess)
            return OciResult<OciSignResult>.Fail(headResult.ErrorKind, headResult.ErrorMessage);

        // 2. GET manifest bytes (the artifact being signed)
        var getResult = await registryClient.GetManifestAsync(
            imageRef.RepositoryPath, imageRef.ManifestReference, ct).ConfigureAwait(false);
        if (!getResult.IsSuccess)
            return OciResult<OciSignResult>.Fail(getResult.ErrorKind, getResult.ErrorMessage);

        var manifestBytes = getResult.Value.Bytes;
        var manifestDescriptor = getResult.Value.Descriptor;

        // 3. Build subject descriptor
        var (sha256, sha512) = HashAlgorithms.ComputeDigests(manifestBytes);
        var fingerprint = KeyFingerprint.Compute(signer.PublicKey);

        var subject = new SubjectDescriptor
        {
            Name = imageRef.FullName,
            Digests = new Dictionary<string, string>
            {
                ["sha256"] = sha256,
                ["sha512"] = sha512
            },
            MediaType = manifestDescriptor.MediaType
        };

        // 4. Build and sign — reuse ArtifactSigner to avoid duplicating signing logic
        var envelope = new SignatureEnvelope { Subject = subject };
        await ArtifactSigner.AppendSignatureAsync(envelope, manifestBytes, signer, fingerprint, label, ct)
            .ConfigureAwait(false);

        // 5. Apply timestamp if requested
        if (tsaUrl is not null)
        {
            var entry = envelope.Signatures[0];
            var tsResult = await TimestampApplier.ApplyAsync(entry, tsaUrl, ct: ct)
                .ConfigureAwait(false);
            if (tsResult.IsSuccess)
                envelope.Signatures[0] = tsResult.Value;
        }

        // 6. Serialize envelope and upload as blob
        var envelopeJson = ArtifactSigner.Serialize(envelope);
        var envelopeBytes = Encoding.UTF8.GetBytes(envelopeJson);

        var blobResult = await registryClient.UploadBlobAsync(
            imageRef.RepositoryPath, envelopeBytes, ct).ConfigureAwait(false);
        if (!blobResult.IsSuccess)
            return OciResult<OciSignResult>.Fail(blobResult.ErrorKind, blobResult.ErrorMessage);

        // 7. Upload empty config blob
        var configResult = await registryClient.UploadBlobAsync(
            imageRef.RepositoryPath, SignatureManifestBuilder.EmptyConfig, ct).ConfigureAwait(false);
        if (!configResult.IsSuccess)
            return OciResult<OciSignResult>.Fail(configResult.ErrorKind, configResult.ErrorMessage);

        // 8. Build and push signature manifest
        var sigManifest = SignatureManifestBuilder.Build(manifestDescriptor, envelopeBytes);
        var sigManifestBytes = Encoding.UTF8.GetBytes(sigManifest.Serialize());
        var sigManifestDigest = $"sha256:{HashAlgorithms.Sha256Hex(sigManifestBytes)}";

        var pushResult = await registryClient.PushManifestAsync(
            imageRef.RepositoryPath, sigManifestDigest, sigManifestBytes,
            OciMediaTypes.OciManifestV1, ct).ConfigureAwait(false);
        if (!pushResult.IsSuccess)
            return OciResult<OciSignResult>.Fail(pushResult.ErrorKind, pushResult.ErrorMessage);

        return OciResult<OciSignResult>.Ok(new OciSignResult
        {
            ManifestDigest = manifestDescriptor.Digest,
            SignatureDigest = pushResult.Value,
            KeyId = fingerprint.Value,
            Algorithm = signer.Algorithm.ToCanonicalName()
        });
    }
}
