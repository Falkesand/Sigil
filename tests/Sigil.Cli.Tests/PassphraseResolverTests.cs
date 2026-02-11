using Sigil.Cli.Commands;

namespace Sigil.Cli.Tests;

public class PassphraseResolverTests : IDisposable
{
    private readonly string _tempDir;

    public PassphraseResolverTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "sigil-pass-test-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    private string WritePassphraseFile(string content)
    {
        var path = Path.Combine(_tempDir, Guid.NewGuid().ToString("N") + ".txt");
        File.WriteAllText(path, content);
        return path;
    }

    [Fact]
    public void Resolve_CliPassphrase_ReturnsCli()
    {
        var result = PassphraseResolver.Resolve("my-secret", null, new FakePrompter(false, null));

        Assert.Equal("my-secret", result);
    }

    [Fact]
    public void Resolve_CliPassphraseFile_ReadsFile()
    {
        var path = WritePassphraseFile("file-secret");

        var result = PassphraseResolver.Resolve(null, path, new FakePrompter(false, null));

        Assert.Equal("file-secret", result);
    }

    [Fact]
    public void Resolve_CliPassphraseFile_TrimsNewline()
    {
        var path = WritePassphraseFile("file-secret\n");

        var result = PassphraseResolver.Resolve(null, path, new FakePrompter(false, null));

        Assert.Equal("file-secret", result);
    }

    [Fact]
    public void Resolve_CliPassphraseFile_TrimsCrLf()
    {
        var path = WritePassphraseFile("file-secret\r\n");

        var result = PassphraseResolver.Resolve(null, path, new FakePrompter(false, null));

        Assert.Equal("file-secret", result);
    }

    [Fact]
    public void Resolve_CliPassphraseFile_SkipsBom()
    {
        // Write file with UTF-8 BOM prefix
        var path = Path.Combine(_tempDir, Guid.NewGuid().ToString("N") + ".txt");
        var bom = new byte[] { 0xEF, 0xBB, 0xBF };
        var content = System.Text.Encoding.UTF8.GetBytes("bom-secret\n");
        var combined = new byte[bom.Length + content.Length];
        bom.CopyTo(combined, 0);
        content.CopyTo(combined, bom.Length);
        File.WriteAllBytes(path, combined);

        var result = PassphraseResolver.Resolve(null, path, new FakePrompter(false, null));

        Assert.Equal("bom-secret", result);
    }

    [Fact]
    public void Resolve_CliPassphraseFile_FileNotFound_ThrowsIOException()
    {
        var fakePath = Path.Combine(_tempDir, "nonexistent.txt");

        Assert.Throws<FileNotFoundException>(() =>
            PassphraseResolver.Resolve(null, fakePath, new FakePrompter(false, null)));
    }

    [Fact]
    public async Task Resolve_EnvVar_ReturnsEnvVar()
    {
        var result = await CommandTestHelper.RunWithEnvVarsAsync(
            new Dictionary<string, string?> { ["SIGIL_PASSPHRASE"] = "env-secret" },
            () => Task.FromResult(
                PassphraseResolver.Resolve(null, null, new FakePrompter(false, null))));

        Assert.Equal("env-secret", result);
    }

    [Fact]
    public async Task Resolve_EnvVarFile_ReadsFile()
    {
        var path = WritePassphraseFile("env-file-secret\n");

        var result = await CommandTestHelper.RunWithEnvVarsAsync(
            new Dictionary<string, string?> { ["SIGIL_PASSPHRASE_FILE"] = path },
            () => Task.FromResult(
                PassphraseResolver.Resolve(null, null, new FakePrompter(false, null))));

        Assert.Equal("env-file-secret", result);
    }

    [Fact]
    public async Task Resolve_InteractivePrompt_WhenTTY()
    {
        var result = await CommandTestHelper.RunWithEnvVarsAsync(
            new Dictionary<string, string?> { ["SIGIL_PASSPHRASE"] = null, ["SIGIL_PASSPHRASE_FILE"] = null },
            () =>
            {
                var prompter = new FakePrompter(isInteractive: true, response: "prompted-secret");
                return Task.FromResult(PassphraseResolver.Resolve(null, null, prompter));
            });

        Assert.Equal("prompted-secret", result);
    }

    [Fact]
    public async Task Resolve_NoPrompt_WhenNotTTY()
    {
        var result = await CommandTestHelper.RunWithEnvVarsAsync(
            new Dictionary<string, string?> { ["SIGIL_PASSPHRASE"] = null, ["SIGIL_PASSPHRASE_FILE"] = null },
            () =>
            {
                var prompter = new FakePrompter(isInteractive: false, response: "should-not-be-used");
                return Task.FromResult(PassphraseResolver.Resolve(null, null, prompter));
            });

        Assert.Null(result);
    }

    [Fact]
    public async Task Resolve_AllNull_ReturnsNull()
    {
        var result = await CommandTestHelper.RunWithEnvVarsAsync(
            new Dictionary<string, string?> { ["SIGIL_PASSPHRASE"] = null, ["SIGIL_PASSPHRASE_FILE"] = null },
            () => Task.FromResult(
                PassphraseResolver.Resolve(null, null, new FakePrompter(false, null))));

        Assert.Null(result);
    }

    [Fact]
    public async Task Resolve_Priority_CliOverEnvVar()
    {
        var result = await CommandTestHelper.RunWithEnvVarsAsync(
            new Dictionary<string, string?> { ["SIGIL_PASSPHRASE"] = "env-secret" },
            () => Task.FromResult(
                PassphraseResolver.Resolve("cli-secret", null, new FakePrompter(false, null))));

        Assert.Equal("cli-secret", result);
    }

    [Fact]
    public async Task Resolve_Priority_CliFileOverEnvVar()
    {
        var path = WritePassphraseFile("file-secret");

        var result = await CommandTestHelper.RunWithEnvVarsAsync(
            new Dictionary<string, string?> { ["SIGIL_PASSPHRASE"] = "env-secret" },
            () => Task.FromResult(
                PassphraseResolver.Resolve(null, path, new FakePrompter(false, null))));

        Assert.Equal("file-secret", result);
    }

    [Fact]
    public async Task Resolve_Priority_EnvVarOverEnvVarFile()
    {
        var path = WritePassphraseFile("env-file-secret");

        var result = await CommandTestHelper.RunWithEnvVarsAsync(
            new Dictionary<string, string?>
            {
                ["SIGIL_PASSPHRASE"] = "env-secret",
                ["SIGIL_PASSPHRASE_FILE"] = path
            },
            () => Task.FromResult(
                PassphraseResolver.Resolve(null, null, new FakePrompter(false, null))));

        Assert.Equal("env-secret", result);
    }

    [Fact]
    public async Task Resolve_NoPrompt_WhenDisabled()
    {
        var result = await CommandTestHelper.RunWithEnvVarsAsync(
            new Dictionary<string, string?> { ["SIGIL_PASSPHRASE"] = null, ["SIGIL_PASSPHRASE_FILE"] = null },
            () =>
            {
                var prompter = new FakePrompter(isInteractive: true, response: "should-not-be-used");
                return Task.FromResult(
                    PassphraseResolver.Resolve(null, null, prompter, allowInteractivePrompt: false));
            });

        Assert.Null(result);
    }

    // --- Credential Store tests ---

    [Fact]
    public async Task Resolve_CredentialStore_ReturnsStoredPassphrase()
    {
        var fakeStore = new FakeCredentialStore();
        var keyPath = Path.Combine(_tempDir, "test.pem");
        var targetName = PassphraseResolver.BuildTargetName(keyPath);
        fakeStore.StorePassphrase(targetName, "cred-secret");

        var result = await CommandTestHelper.RunWithEnvVarsAsync(
            new Dictionary<string, string?> { ["SIGIL_PASSPHRASE"] = null, ["SIGIL_PASSPHRASE_FILE"] = null },
            () => Task.FromResult(
                PassphraseResolver.Resolve(null, null, new FakePrompter(false, null),
                    keyPath: keyPath, credentialStore: fakeStore)));

        Assert.Equal("cred-secret", result);
    }

    [Fact]
    public async Task Resolve_CredentialStore_SkippedWhenKeyPathNull()
    {
        var fakeStore = new FakeCredentialStore();
        fakeStore.StorePassphrase("sigil:passphrase:anything", "should-not-return");

        var result = await CommandTestHelper.RunWithEnvVarsAsync(
            new Dictionary<string, string?> { ["SIGIL_PASSPHRASE"] = null, ["SIGIL_PASSPHRASE_FILE"] = null },
            () => Task.FromResult(
                PassphraseResolver.Resolve(null, null, new FakePrompter(false, null),
                    keyPath: null, credentialStore: fakeStore)));

        Assert.Null(result);
    }

    [Fact]
    public async Task Resolve_CredentialStore_NotFoundFallsThrough()
    {
        var fakeStore = new FakeCredentialStore(); // empty
        var keyPath = Path.Combine(_tempDir, "test.pem");

        var result = await CommandTestHelper.RunWithEnvVarsAsync(
            new Dictionary<string, string?> { ["SIGIL_PASSPHRASE"] = null, ["SIGIL_PASSPHRASE_FILE"] = null },
            () =>
            {
                var prompter = new FakePrompter(isInteractive: true, response: "prompted");
                return Task.FromResult(
                    PassphraseResolver.Resolve(null, null, prompter,
                        keyPath: keyPath, credentialStore: fakeStore));
            });

        Assert.Equal("prompted", result);
    }

    [Fact]
    public void Resolve_Priority_CliOverCredentialStore()
    {
        var fakeStore = new FakeCredentialStore();
        var keyPath = Path.Combine(_tempDir, "test.pem");
        fakeStore.StorePassphrase(PassphraseResolver.BuildTargetName(keyPath), "cred-secret");

        var result = PassphraseResolver.Resolve("cli-secret", null, new FakePrompter(false, null),
            keyPath: keyPath, credentialStore: fakeStore);

        Assert.Equal("cli-secret", result);
    }

    [Fact]
    public async Task Resolve_Priority_EnvVarOverCredentialStore()
    {
        var fakeStore = new FakeCredentialStore();
        var keyPath = Path.Combine(_tempDir, "test.pem");
        fakeStore.StorePassphrase(PassphraseResolver.BuildTargetName(keyPath), "cred-secret");

        var result = await CommandTestHelper.RunWithEnvVarsAsync(
            new Dictionary<string, string?> { ["SIGIL_PASSPHRASE"] = "env-secret", ["SIGIL_PASSPHRASE_FILE"] = null },
            () => Task.FromResult(
                PassphraseResolver.Resolve(null, null, new FakePrompter(false, null),
                    keyPath: keyPath, credentialStore: fakeStore)));

        Assert.Equal("env-secret", result);
    }

    [Fact]
    public async Task Resolve_Priority_CredentialStoreOverPrompt()
    {
        var fakeStore = new FakeCredentialStore();
        var keyPath = Path.Combine(_tempDir, "test.pem");
        fakeStore.StorePassphrase(PassphraseResolver.BuildTargetName(keyPath), "cred-secret");

        var result = await CommandTestHelper.RunWithEnvVarsAsync(
            new Dictionary<string, string?> { ["SIGIL_PASSPHRASE"] = null, ["SIGIL_PASSPHRASE_FILE"] = null },
            () =>
            {
                var prompter = new FakePrompter(isInteractive: true, response: "prompted");
                return Task.FromResult(
                    PassphraseResolver.Resolve(null, null, prompter,
                        keyPath: keyPath, credentialStore: fakeStore));
            });

        Assert.Equal("cred-secret", result);
    }

    [Fact]
    public void BuildTargetName_NormalizesPath()
    {
        var keyPath = Path.Combine(_tempDir, "keys", "..", "test.pem");
        var expected = Path.Combine(_tempDir, "test.pem");

        var targetName = PassphraseResolver.BuildTargetName(keyPath);

        Assert.Equal($"sigil:passphrase:{expected}", targetName);
    }

    [Fact]
    public void Resolve_CliPassphraseFile_OverCredentialStore()
    {
        var path = WritePassphraseFile("file-secret");
        var fakeStore = new FakeCredentialStore();
        var keyPath = Path.Combine(_tempDir, "test.pem");
        fakeStore.StorePassphrase(PassphraseResolver.BuildTargetName(keyPath), "cred-secret");

        var result = PassphraseResolver.Resolve(null, path, new FakePrompter(false, null),
            keyPath: keyPath, credentialStore: fakeStore);

        Assert.Equal("file-secret", result);
    }

    private sealed class FakePrompter : IConsolePrompter
    {
        private readonly string? _response;

        public FakePrompter(bool isInteractive, string? response)
        {
            IsInteractive = isInteractive;
            _response = response;
        }

        public bool IsInteractive { get; }

        public string? ReadPassphrase(string prompt) => _response;
    }

    private sealed class FakeCredentialStore : ICredentialStore
    {
        private readonly Dictionary<string, string> _store = new(StringComparer.Ordinal);

        public void StorePassphrase(string targetName, string secret) => _store[targetName] = secret;

        public CredentialStoreResult<string> Retrieve(string targetName)
        {
            if (_store.TryGetValue(targetName, out var value))
                return CredentialStoreResult<string>.Ok(value);
            return CredentialStoreResult<string>.Fail(
                CredentialStoreErrorKind.NotFound, $"Not found: {targetName}");
        }

        public CredentialStoreResult<bool> Store(string targetName, string secret)
        {
            _store[targetName] = secret;
            return CredentialStoreResult<bool>.Ok(true);
        }

        public CredentialStoreResult<bool> Delete(string targetName)
        {
            if (_store.Remove(targetName))
                return CredentialStoreResult<bool>.Ok(true);
            return CredentialStoreResult<bool>.Fail(
                CredentialStoreErrorKind.NotFound, $"Not found: {targetName}");
        }

        public CredentialStoreResult<IReadOnlyList<string>> List(string prefix)
        {
            var matches = _store.Keys.Where(k => k.StartsWith(prefix, StringComparison.Ordinal)).ToList();
            return CredentialStoreResult<IReadOnlyList<string>>.Ok(matches);
        }
    }
}
