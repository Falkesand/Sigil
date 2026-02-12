using System.Diagnostics.CodeAnalysis;

namespace Sigil.Anomaly;

[SuppressMessage("Design", "CA1000:Do not declare static members on generic types", Justification = "Factory methods for idiomatic Result pattern")]
public readonly record struct AnomalyResult<T>
{
    private readonly T? _value;
    private readonly AnomalyErrorKind _errorKind;
    private readonly string? _errorMessage;

    public bool IsSuccess { get; }

    public T Value => IsSuccess
        ? _value!
        : throw new InvalidOperationException("Cannot access Value on a failed result.");

    public AnomalyErrorKind ErrorKind => !IsSuccess
        ? _errorKind
        : throw new InvalidOperationException("Cannot access ErrorKind on a successful result.");

    public string ErrorMessage => !IsSuccess
        ? _errorMessage!
        : throw new InvalidOperationException("Cannot access ErrorMessage on a successful result.");

    private AnomalyResult(T value)
    {
        IsSuccess = true;
        _value = value;
        _errorKind = default;
        _errorMessage = null;
    }

    private AnomalyResult(AnomalyErrorKind errorKind, string errorMessage)
    {
        IsSuccess = false;
        _value = default;
        _errorKind = errorKind;
        _errorMessage = errorMessage;
    }

    public static AnomalyResult<T> Ok(T value) => new(value);

    public static AnomalyResult<T> Fail(AnomalyErrorKind errorKind, string errorMessage) => new(errorKind, errorMessage);
}
