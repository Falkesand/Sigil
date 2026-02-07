using Secure.Sbom.Crypto;
using System.Text;

namespace Secure.Sbom.Core.Tests.Crypto;

public class HashAlgorithmsTests
{
    [Fact]
    public void Sha256_KnownVector_ReturnsExpectedHash()
    {
        // SHA-256 of "" (empty string)
        var hash = HashAlgorithms.Sha256Hex([]);
        Assert.Equal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hash);
    }

    [Fact]
    public void Sha256_HelloWorld_ReturnsExpectedHash()
    {
        var data = Encoding.UTF8.GetBytes("hello world");
        var hash = HashAlgorithms.Sha256Hex(data);
        Assert.Equal("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9", hash);
    }

    [Fact]
    public void Sha512_KnownVector_ReturnsExpectedHash()
    {
        var hash = HashAlgorithms.Sha512Hex([]);
        Assert.Equal(
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
            hash);
    }

    [Fact]
    public void ComputeDigests_ReturnsBothHashes()
    {
        var data = Encoding.UTF8.GetBytes("test data");
        var (sha256, sha512) = HashAlgorithms.ComputeDigests(data);

        Assert.NotNull(sha256);
        Assert.NotNull(sha512);
        Assert.Equal(64, sha256.Length);   // 32 bytes hex = 64 chars
        Assert.Equal(128, sha512.Length);  // 64 bytes hex = 128 chars
    }

    [Fact]
    public void ComputeDigests_Stream_MatchesByteVersion()
    {
        var data = Encoding.UTF8.GetBytes("stream test");
        var (sha256Bytes, sha512Bytes) = HashAlgorithms.ComputeDigests(data);

        using var stream = new MemoryStream(data);
        var (sha256Stream, sha512Stream) = HashAlgorithms.ComputeDigests(stream);

        Assert.Equal(sha256Bytes, sha256Stream);
        Assert.Equal(sha512Bytes, sha512Stream);
    }
}
