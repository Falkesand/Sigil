using Sigil.Timestamping;

namespace Sigil.Core.Tests.Timestamping;

public class TimestampValidatorTests
{
    [Fact]
    public void InvalidBase64_returns_invalid()
    {
        var result = TimestampValidator.Validate("!!!not-base64!!!", [1, 2, 3]);

        Assert.False(result.IsValid);
        Assert.Contains("base64", result.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void GarbageBytes_returns_invalid()
    {
        var garbage = Convert.ToBase64String([0x00, 0x01, 0x02, 0x03]);

        var result = TimestampValidator.Validate(garbage, [1, 2, 3]);

        Assert.False(result.IsValid);
        Assert.NotNull(result.Error);
    }

    [Fact]
    public void ValidToken_returns_timestamp()
    {
        var signatureBytes = new byte[] { 0xCA, 0xFE, 0xBA, 0xBE };
        var tokenBytes = TimestampTestFixture.CreateTimestampToken(signatureBytes);
        var base64Token = Convert.ToBase64String(tokenBytes);

        var result = TimestampValidator.Validate(base64Token, signatureBytes);

        Assert.True(result.IsValid, $"Validation failed: {result.Error}");
        Assert.Null(result.Error);
        Assert.True(result.Timestamp > DateTimeOffset.MinValue);
    }

    [Fact]
    public void HashMismatch_returns_invalid()
    {
        var tokenBytes = TimestampTestFixture.CreateMismatchedToken();
        var base64Token = Convert.ToBase64String(tokenBytes);

        var result = TimestampValidator.Validate(base64Token, [0xDE, 0xAD, 0xBE, 0xEF]);

        Assert.False(result.IsValid);
        Assert.Contains("hash", result.Error!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ValidToken_returns_correct_timestamp()
    {
        var expectedTimestamp = new DateTimeOffset(2026, 1, 15, 12, 0, 0, TimeSpan.Zero);
        var signatureBytes = new byte[] { 0x01, 0x02, 0x03 };
        var tokenBytes = TimestampTestFixture.CreateTimestampToken(signatureBytes, expectedTimestamp);
        var base64Token = Convert.ToBase64String(tokenBytes);

        var result = TimestampValidator.Validate(base64Token, signatureBytes);

        Assert.True(result.IsValid, $"Validation failed: {result.Error}");
        Assert.Equal(expectedTimestamp, result.Timestamp);
    }
}
