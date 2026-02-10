using Sigil.Signing;
using Sigil.Transparency.Remote;

namespace Sigil.Core.Tests.Transparency.Remote;

public class LogSubmitterTests
{
    private static SignatureEntry CreateEntry() => new()
    {
        KeyId = "sha256:abcdef",
        Algorithm = "ecdsa-p256",
        PublicKey = "AQID",
        Value = "BAUG",
        Timestamp = "2026-02-10T12:00:00Z",
        Label = "release",
        TimestampToken = "dGVzdA==",
        OidcToken = "jwt.token.here",
        OidcIssuer = "https://accounts.google.com",
        OidcIdentity = "user@example.com"
    };

    private static SubjectDescriptor CreateSubject() => new()
    {
        Name = "test.txt",
        Digests = new Dictionary<string, string> { ["sha256"] = "abc123" }
    };

    [Fact]
    public async Task SubmitAsync_success_returns_entry_with_transparency_fields()
    {
        var log = new FakeRemoteLog(RemoteLogResult<TransparencyReceipt>.Ok(new TransparencyReceipt
        {
            LogUrl = "https://log.example.com",
            LogIndex = 42,
            SignedCheckpoint = "Y2hlY2twb2ludA==",
            InclusionProof = new RemoteInclusionProof
            {
                LeafIndex = 42,
                TreeSize = 100,
                RootHash = "aabbccdd",
                Hashes = ["1111"]
            }
        }));

        var result = await LogSubmitter.SubmitAsync(CreateEntry(), CreateSubject(), log);

        Assert.True(result.IsSuccess);
        var entry = result.Value;
        Assert.Equal("https://log.example.com", entry.TransparencyLogUrl);
        Assert.Equal(42, entry.TransparencyLogIndex);
        Assert.Equal("Y2hlY2twb2ludA==", entry.TransparencySignedCheckpoint);
        Assert.NotNull(entry.TransparencyInclusionProof);
    }

    [Fact]
    public async Task SubmitAsync_preserves_all_existing_fields()
    {
        var original = CreateEntry();
        var log = new FakeRemoteLog(RemoteLogResult<TransparencyReceipt>.Ok(new TransparencyReceipt
        {
            LogUrl = "https://log.example.com",
            LogIndex = 1,
            SignedCheckpoint = "cp",
            InclusionProof = new RemoteInclusionProof
            {
                LeafIndex = 1, TreeSize = 1, RootHash = "aa", Hashes = []
            }
        }));

        var result = await LogSubmitter.SubmitAsync(original, CreateSubject(), log);

        Assert.True(result.IsSuccess);
        var entry = result.Value;
        Assert.Equal(original.KeyId, entry.KeyId);
        Assert.Equal(original.Algorithm, entry.Algorithm);
        Assert.Equal(original.PublicKey, entry.PublicKey);
        Assert.Equal(original.Value, entry.Value);
        Assert.Equal(original.Timestamp, entry.Timestamp);
        Assert.Equal(original.Label, entry.Label);
        Assert.Equal(original.TimestampToken, entry.TimestampToken);
        Assert.Equal(original.OidcToken, entry.OidcToken);
        Assert.Equal(original.OidcIssuer, entry.OidcIssuer);
        Assert.Equal(original.OidcIdentity, entry.OidcIdentity);
    }

    [Fact]
    public async Task SubmitAsync_failure_propagates_error()
    {
        var log = new FakeRemoteLog(RemoteLogResult<TransparencyReceipt>.Fail(
            RemoteLogErrorKind.NetworkError, "connection refused"));

        var result = await LogSubmitter.SubmitAsync(CreateEntry(), CreateSubject(), log);

        Assert.False(result.IsSuccess);
        Assert.Equal(RemoteLogErrorKind.NetworkError, result.ErrorKind);
        Assert.Equal("connection refused", result.ErrorMessage);
    }

    [Fact]
    public async Task SubmitAsync_null_entry_throws()
    {
        var log = new FakeRemoteLog(RemoteLogResult<TransparencyReceipt>.Fail(
            RemoteLogErrorKind.ServerError, "error"));

        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            LogSubmitter.SubmitAsync(null!, CreateSubject(), log));
    }

    private sealed class FakeRemoteLog : IRemoteLog
    {
        private readonly RemoteLogResult<TransparencyReceipt> _appendResult;

        public FakeRemoteLog(RemoteLogResult<TransparencyReceipt> appendResult)
        {
            _appendResult = appendResult;
        }

        public string LogUrl => "https://fake.log";

        public Task<RemoteLogResult<TransparencyReceipt>> AppendAsync(
            SignatureEntry entry, SubjectDescriptor subject, CancellationToken ct = default)
            => Task.FromResult(_appendResult);

        public Task<RemoteLogResult<SignedCheckpoint>> GetCheckpointAsync(CancellationToken ct = default)
            => throw new NotImplementedException();

        public Task<RemoteLogResult<RemoteInclusionProof>> GetInclusionProofAsync(
            long leafIndex, CancellationToken ct = default)
            => throw new NotImplementedException();

        public Task<RemoteLogResult<string>> GetPublicKeyAsync(CancellationToken ct = default)
            => throw new NotImplementedException();

        public void Dispose() { }
    }
}
