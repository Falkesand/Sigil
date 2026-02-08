using System.Diagnostics.CodeAnalysis;

namespace Sigil.Attestation;

[SuppressMessage("Design", "CA1000:Do not declare static members on generic types",
    Justification = "Factory methods Ok/Fail are the idiomatic API for Result types")]
public readonly record struct AttestationResult<T>
{
    private readonly T? _value;
    private readonly AttestationErrorKind? _errorKind;
    private readonly string? _errorMessage;

    public bool IsSuccess { get; }

    public T Value => IsSuccess
        ? _value!
        : throw new InvalidOperationException("Cannot access Value on a failed result.");

    public AttestationErrorKind ErrorKind => !IsSuccess
        ? _errorKind!.Value
        : throw new InvalidOperationException("Cannot access ErrorKind on a successful result.");

    public string ErrorMessage => !IsSuccess
        ? _errorMessage!
        : throw new InvalidOperationException("Cannot access ErrorMessage on a successful result.");

    private AttestationResult(T? value, AttestationErrorKind? errorKind, string? errorMessage, bool isSuccess)
    {
        _value = value;
        _errorKind = errorKind;
        _errorMessage = errorMessage;
        IsSuccess = isSuccess;
    }

    public static AttestationResult<T> Ok(T value) => new(value, null, null, true);

    public static AttestationResult<T> Fail(AttestationErrorKind errorKind, string errorMessage) =>
        new(default, errorKind, errorMessage, false);
}
