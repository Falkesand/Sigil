using Sigil.Cli.Commands;

namespace Sigil.Cli.Tests;

public class WindowsCredentialStoreTests : IDisposable
{
    private readonly string _testPrefix;
    private readonly List<string> _createdTargets = [];

    public WindowsCredentialStoreTests()
    {
        _testPrefix = $"sigil:test:{Guid.NewGuid():N}:";
    }

    public void Dispose()
    {
        if (!OperatingSystem.IsWindows())
            return;

        var store = new WindowsCredentialStore();
        foreach (var target in _createdTargets)
        {
            store.Delete(target);
        }
    }

    [Fact]
    public void Store_And_Retrieve_RoundTrips()
    {
        if (!OperatingSystem.IsWindows()) return;

        var store = new WindowsCredentialStore();
        var target = _testPrefix + "roundtrip";
        _createdTargets.Add(target);

        var storeResult = store.Store(target, "my-secret-passphrase");
        Assert.True(storeResult.IsSuccess);

        var retrieveResult = store.Retrieve(target);
        Assert.True(retrieveResult.IsSuccess);
        Assert.Equal("my-secret-passphrase", retrieveResult.Value);
    }

    [Fact]
    public void Retrieve_NotFound_ReturnsError()
    {
        if (!OperatingSystem.IsWindows()) return;

        var store = new WindowsCredentialStore();
        var target = _testPrefix + "nonexistent";

        var result = store.Retrieve(target);
        Assert.False(result.IsSuccess);
        Assert.Equal(CredentialStoreErrorKind.NotFound, result.ErrorKind);
    }

    [Fact]
    public void Delete_Existing_Succeeds()
    {
        if (!OperatingSystem.IsWindows()) return;

        var store = new WindowsCredentialStore();
        var target = _testPrefix + "delete-me";
        store.Store(target, "temp");

        var result = store.Delete(target);
        Assert.True(result.IsSuccess);

        var retrieveResult = store.Retrieve(target);
        Assert.False(retrieveResult.IsSuccess);
        Assert.Equal(CredentialStoreErrorKind.NotFound, retrieveResult.ErrorKind);
    }

    [Fact]
    public void Delete_NotFound_ReturnsError()
    {
        if (!OperatingSystem.IsWindows()) return;

        var store = new WindowsCredentialStore();
        var target = _testPrefix + "not-there";

        var result = store.Delete(target);
        Assert.False(result.IsSuccess);
        Assert.Equal(CredentialStoreErrorKind.NotFound, result.ErrorKind);
    }

    [Fact]
    public void List_ReturnsMatchingTargets()
    {
        if (!OperatingSystem.IsWindows()) return;

        var store = new WindowsCredentialStore();
        var target1 = _testPrefix + "list-a";
        var target2 = _testPrefix + "list-b";
        _createdTargets.Add(target1);
        _createdTargets.Add(target2);

        store.Store(target1, "secret-a");
        store.Store(target2, "secret-b");

        var result = store.List(_testPrefix);
        Assert.True(result.IsSuccess);
        Assert.Contains(target1, result.Value);
        Assert.Contains(target2, result.Value);
    }

    [Fact]
    public void List_NoMatches_ReturnsEmpty()
    {
        if (!OperatingSystem.IsWindows()) return;

        var store = new WindowsCredentialStore();

        var result = store.List(_testPrefix + "no-match-");
        Assert.True(result.IsSuccess);
        Assert.Empty(result.Value);
    }

    [Fact]
    public void Store_Overwrite_UpdatesValue()
    {
        if (!OperatingSystem.IsWindows()) return;

        var store = new WindowsCredentialStore();
        var target = _testPrefix + "overwrite";
        _createdTargets.Add(target);

        store.Store(target, "first");
        store.Store(target, "second");

        var result = store.Retrieve(target);
        Assert.True(result.IsSuccess);
        Assert.Equal("second", result.Value);
    }

    [Fact]
    public void Retrieve_EmptyTarget_ReturnsInvalidTarget()
    {
        if (!OperatingSystem.IsWindows()) return;

        var store = new WindowsCredentialStore();

        var result = store.Retrieve("  ");
        Assert.False(result.IsSuccess);
        Assert.Equal(CredentialStoreErrorKind.InvalidTarget, result.ErrorKind);
    }

    [Fact]
    public void Store_TargetNameExceedsMaxLength_ReturnsInvalidTarget()
    {
        if (!OperatingSystem.IsWindows()) return;

        var store = new WindowsCredentialStore();
        var longTarget = new string('a', 400);

        var result = store.Store(longTarget, "secret");
        Assert.False(result.IsSuccess);
        Assert.Equal(CredentialStoreErrorKind.InvalidTarget, result.ErrorKind);
    }

    [Fact]
    public void CredentialStoreFactory_ReturnsStoreOnWindows()
    {
        var store = CredentialStoreFactory.TryCreate();

        if (OperatingSystem.IsWindows())
            Assert.NotNull(store);
        else
            Assert.Null(store);
    }
}
