using System.Text.Json;
using Sigil.Signing;

namespace Sigil.Oci;

/// <summary>
/// Orchestrates verification of OCI image signatures:
/// HEAD → referrers → fetch each signature → verify against manifest.
/// </summary>
public static class OciImageVerifier
{
    /// <summary>
    /// Verifies all Sigil signatures attached to an OCI image.
    /// </summary>
    public static async Task<OciResult<OciVerificationResult>> VerifyAsync(
        OciRegistryClient registryClient,
        ImageReference imageRef,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(registryClient);
        ArgumentNullException.ThrowIfNull(imageRef);

        // 1. HEAD manifest to get digest
        var headResult = await registryClient.HeadManifestAsync(
            imageRef.RepositoryPath, imageRef.ManifestReference, ct).ConfigureAwait(false);
        if (!headResult.IsSuccess)
            return OciResult<OciVerificationResult>.Fail(headResult.ErrorKind, headResult.ErrorMessage);

        var manifestDigest = headResult.Value.Digest;

        // 2. Get referrers filtered by Sigil artifact type
        var referrersResult = await registryClient.GetReferrersAsync(
            imageRef.RepositoryPath, manifestDigest, OciMediaTypes.SigilSignature, ct).ConfigureAwait(false);
        if (!referrersResult.IsSuccess)
            return OciResult<OciVerificationResult>.Fail(referrersResult.ErrorKind, referrersResult.ErrorMessage);

        var sigReferrers = referrersResult.Value;
        if (sigReferrers.Count == 0)
        {
            return OciResult<OciVerificationResult>.Fail(OciErrorKind.SignatureNotFound,
                "No Sigil signatures found for this image.");
        }

        // 3. GET the signed manifest bytes
        var getManifestResult = await registryClient.GetManifestAsync(
            imageRef.RepositoryPath, imageRef.ManifestReference, ct).ConfigureAwait(false);
        if (!getManifestResult.IsSuccess)
            return OciResult<OciVerificationResult>.Fail(getManifestResult.ErrorKind, getManifestResult.ErrorMessage);

        var manifestBytes = getManifestResult.Value.Bytes;

        // 4. For each signature referrer: fetch manifest → fetch layer blob → verify
        var results = new List<VerificationResult>();
        foreach (var referrer in sigReferrers)
        {
            var verifyResult = await VerifySingleSignatureAsync(
                registryClient, imageRef.RepositoryPath, referrer, manifestBytes, ct).ConfigureAwait(false);
            if (verifyResult is not null)
                results.Add(verifyResult);
        }

        return OciResult<OciVerificationResult>.Ok(new OciVerificationResult
        {
            ManifestDigest = manifestDigest,
            SignatureResults = results
        });
    }

    private static async Task<VerificationResult?> VerifySingleSignatureAsync(
        OciRegistryClient registryClient,
        string repository,
        OciDescriptor sigReferrer,
        byte[] manifestBytes,
        CancellationToken ct)
    {
        // GET the signature artifact manifest
        var sigManifestResult = await registryClient.GetManifestAsync(
            repository, sigReferrer.Digest, ct).ConfigureAwait(false);
        if (!sigManifestResult.IsSuccess)
            return null;

        var sigManifest = sigManifestResult.Value.Manifest;
        if (sigManifest.Layers.Count == 0)
            return null;

        // GET the signature envelope blob (first layer)
        var blobResult = await registryClient.GetBlobAsync(
            repository, sigManifest.Layers[0].Digest, ct).ConfigureAwait(false);
        if (!blobResult.IsSuccess)
            return null;

        // Parse the envelope
        SignatureEnvelope? envelope;
        try
        {
            envelope = JsonSerializer.Deserialize<SignatureEnvelope>(blobResult.Value);
        }
        catch (JsonException)
        {
            return null;
        }

        if (envelope is null)
            return null;

        // Verify signature against manifest bytes
        return SignatureValidator.Verify(manifestBytes, envelope);
    }
}
