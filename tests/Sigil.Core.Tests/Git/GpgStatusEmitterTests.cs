using System.Globalization;
using Sigil.Git;

namespace Sigil.Core.Tests.Git;

public class GpgStatusEmitterTests
{
    private const string TestFingerprint = "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

    [Fact]
    public void SigCreated_emits_correct_format()
    {
        var ts = DateTimeOffset.Parse("2026-01-15T10:30:00Z", CultureInfo.InvariantCulture);

        var result = GpgStatusEmitter.SigCreated("ecdsa-p256", TestFingerprint, ts);

        Assert.StartsWith("[GNUPG:] SIG_CREATED D ecdsa-p256 8 00 ", result);
        Assert.Contains(TestFingerprint, result);
    }

    [Fact]
    public void GoodSig_emits_correct_format()
    {
        var result = GpgStatusEmitter.GoodSig(TestFingerprint);

        Assert.Equal($"[GNUPG:] GOODSIG {TestFingerprint} {TestFingerprint}", result);
    }

    [Fact]
    public void BadSig_emits_correct_format()
    {
        var result = GpgStatusEmitter.BadSig(TestFingerprint);

        Assert.Equal($"[GNUPG:] BADSIG {TestFingerprint} {TestFingerprint}", result);
    }

    [Fact]
    public void ValidSig_emits_correct_format()
    {
        var ts = DateTimeOffset.Parse("2026-01-15T10:30:00Z", CultureInfo.InvariantCulture);

        var result = GpgStatusEmitter.ValidSig(TestFingerprint, ts, "ecdsa-p256");

        Assert.StartsWith("[GNUPG:] VALIDSIG", result);
        Assert.Contains(TestFingerprint, result);
        Assert.Contains("2026-01-15", result);
        Assert.Contains("ecdsa-p256", result);
    }

    [Fact]
    public void NewSig_emits_correct_format()
    {
        Assert.Equal("[GNUPG:] NEWSIG", GpgStatusEmitter.NewSig());
    }

    [Fact]
    public void TrustFully_and_TrustUndefined_emit_correct_format()
    {
        Assert.Equal("[GNUPG:] TRUST_FULLY 0 sigil", GpgStatusEmitter.TrustFully());
        Assert.Equal("[GNUPG:] TRUST_UNDEFINED 0 sigil", GpgStatusEmitter.TrustUndefined());
    }
}
