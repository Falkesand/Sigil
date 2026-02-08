using Sigil.Attestation;

namespace Sigil.Core.Tests.Attestation;

public class AttestationResultTests
{
    [Fact]
    public void Ok_IsSuccess_true()
    {
        var result = AttestationResult<string>.Ok("hello");

        Assert.True(result.IsSuccess);
        Assert.Equal("hello", result.Value);
    }

    [Fact]
    public void Fail_IsSuccess_false()
    {
        var result = AttestationResult<string>.Fail(
            AttestationErrorKind.InvalidPayloadType, "bad type");

        Assert.False(result.IsSuccess);
        Assert.Equal(AttestationErrorKind.InvalidPayloadType, result.ErrorKind);
        Assert.Equal("bad type", result.ErrorMessage);
    }

    [Fact]
    public void Ok_accessing_ErrorKind_throws()
    {
        var result = AttestationResult<int>.Ok(42);

        Assert.Throws<InvalidOperationException>(() => result.ErrorKind);
    }

    [Fact]
    public void Ok_accessing_ErrorMessage_throws()
    {
        var result = AttestationResult<int>.Ok(42);

        Assert.Throws<InvalidOperationException>(() => result.ErrorMessage);
    }

    [Fact]
    public void Fail_accessing_Value_throws()
    {
        var result = AttestationResult<int>.Fail(
            AttestationErrorKind.SigningFailed, "boom");

        Assert.Throws<InvalidOperationException>(() => result.Value);
    }

    [Fact]
    public void Fail_with_different_error_kinds()
    {
        var kinds = new[]
        {
            AttestationErrorKind.DeserializationFailed,
            AttestationErrorKind.DigestMismatch,
            AttestationErrorKind.VerificationFailed,
            AttestationErrorKind.SubjectMissing,
            AttestationErrorKind.FileNotFound
        };

        foreach (var kind in kinds)
        {
            var result = AttestationResult<string>.Fail(kind, kind.ToString());
            Assert.Equal(kind, result.ErrorKind);
        }
    }
}
