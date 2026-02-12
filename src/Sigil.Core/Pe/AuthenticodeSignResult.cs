using Sigil.Signing;

namespace Sigil.Pe;

/// <summary>
/// Result of Authenticode PE signing: the signed PE bytes and detached Sigil envelope.
/// </summary>
public sealed class AuthenticodeSignResult
{
    public required byte[] SignedPeBytes { get; init; }
    public required SignatureEnvelope Envelope { get; init; }
}
