namespace Sigil.Signing;

/// <summary>
/// Adapts <see cref="ManifestVerificationResult"/> to <see cref="VerificationResult"/>
/// so the existing <see cref="Trust.TrustEvaluator"/> can evaluate manifest signatures unchanged.
/// </summary>
public static class ManifestTrustAdapter
{
    public static VerificationResult ToVerificationResult(ManifestVerificationResult manifest)
    {
        ArgumentNullException.ThrowIfNull(manifest);

        return new VerificationResult
        {
            ArtifactDigestMatch = manifest.AllDigestsMatch,
            Signatures = manifest.Signatures.ToList()
        };
    }
}
