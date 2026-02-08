using System.Text.Json;
using Sigil.Vault.HashiCorp;

namespace Sigil.Vault.HashiCorp.Tests;

public class HashiCorpKeyProviderTests
{
    private const string TestPem = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n-----END PUBLIC KEY-----";

    [Fact]
    public void ExtractPublicKeyPem_WithJsonElement_Object_ExtractsPublicKey()
    {
        // Simulate what VaultSharp returns: a JsonElement representing the version data object
        var json = JsonSerializer.Serialize(new
        {
            creation_time = "2025-01-01T00:00:00Z",
            name = "P-256",
            public_key = TestPem
        });
        var element = JsonSerializer.Deserialize<JsonElement>(json);

        var result = HashiCorpKeyProvider.ExtractPublicKeyPem(element);

        Assert.Equal(TestPem, result);
    }

    [Fact]
    public void ExtractPublicKeyPem_WithJsonElement_String_ReturnsString()
    {
        var json = JsonSerializer.Serialize(TestPem);
        var element = JsonSerializer.Deserialize<JsonElement>(json);

        var result = HashiCorpKeyProvider.ExtractPublicKeyPem(element);

        Assert.Equal(TestPem, result);
    }

    [Fact]
    public void ExtractPublicKeyPem_WithNull_ReturnsNull()
    {
        var result = HashiCorpKeyProvider.ExtractPublicKeyPem(null);

        Assert.Null(result);
    }

    [Fact]
    public void ExtractPublicKeyPem_WithPlainString_ReturnsString()
    {
        var result = HashiCorpKeyProvider.ExtractPublicKeyPem(TestPem);

        Assert.Equal(TestPem, result);
    }

    [Fact]
    public void ExtractPublicKeyPem_WithJsonElement_Object_MissingPublicKey_ReturnsNull()
    {
        var json = JsonSerializer.Serialize(new
        {
            creation_time = "2025-01-01T00:00:00Z",
            name = "P-256"
        });
        var element = JsonSerializer.Deserialize<JsonElement>(json);

        var result = HashiCorpKeyProvider.ExtractPublicKeyPem(element);

        Assert.Null(result);
    }

    [Fact]
    public void ExtractPublicKeyPem_WithJsonElement_Number_ReturnsNull()
    {
        var json = "42";
        var element = JsonSerializer.Deserialize<JsonElement>(json);

        var result = HashiCorpKeyProvider.ExtractPublicKeyPem(element);

        Assert.Null(result);
    }
}
