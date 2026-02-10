namespace Sigil.Trust;

/// <summary>
/// Bundle-level trust evaluation result aggregating per-signature decisions.
/// </summary>
public sealed class TrustEvaluationResult
{
    public required IReadOnlyList<SignatureTrustResult> Signatures { get; init; }

    public bool AnyTrusted => Signatures.Any(s =>
        s.Decision is TrustDecision.Trusted or TrustDecision.TrustedViaEndorsement or TrustDecision.TrustedViaOidc);

    public bool AllTrusted => Signatures.Count > 0 && Signatures.All(s =>
        s.Decision is TrustDecision.Trusted or TrustDecision.TrustedViaEndorsement or TrustDecision.TrustedViaOidc);
}
