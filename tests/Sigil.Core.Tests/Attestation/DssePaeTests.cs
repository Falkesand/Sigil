using System.Text;
using Sigil.Attestation;

namespace Sigil.Core.Tests.Attestation;

public class DssePaeTests
{
    [Fact]
    public void Encode_produces_correct_format()
    {
        var payloadType = "application/vnd.in-toto+json";
        var payload = Encoding.UTF8.GetBytes("test body");

        var pae = DssePae.Encode(payloadType, payload);
        var paeStr = Encoding.UTF8.GetString(pae);

        // "DSSEv1 28 application/vnd.in-toto+json 9 test body"
        Assert.StartsWith("DSSEv1 ", paeStr);
        Assert.Contains("28 application/vnd.in-toto+json", paeStr);
        Assert.Contains("9 test body", paeStr);
    }

    [Fact]
    public void Encode_empty_payload()
    {
        var pae = DssePae.Encode("text/plain", []);
        var paeStr = Encoding.UTF8.GetString(pae);

        Assert.Equal("DSSEv1 10 text/plain 0 ", paeStr);
    }

    [Fact]
    public void Encode_empty_type()
    {
        var payload = "hello"u8.ToArray();
        var pae = DssePae.Encode("", payload);
        var paeStr = Encoding.UTF8.GetString(pae);

        Assert.Equal("DSSEv1 0  5 hello", paeStr);
    }

    [Fact]
    public void Encode_binary_payload_preserved()
    {
        var payload = new byte[] { 0x00, 0xFF, 0x80, 0x01 };

        var pae = DssePae.Encode("application/octet-stream", payload);

        // Verify the binary bytes are at the end
        Assert.Equal(0x00, pae[^4]);
        Assert.Equal(0xFF, pae[^3]);
        Assert.Equal(0x80, pae[^2]);
        Assert.Equal(0x01, pae[^1]);
    }

    [Fact]
    public void Encode_deterministic_same_inputs_same_output()
    {
        var type = "application/vnd.in-toto+json";
        var payload = "same content"u8.ToArray();

        var pae1 = DssePae.Encode(type, payload);
        var pae2 = DssePae.Encode(type, payload);

        Assert.Equal(pae1, pae2);
    }

    [Fact]
    public void Encode_different_types_produce_different_output()
    {
        var payload = "body"u8.ToArray();

        var pae1 = DssePae.Encode("type-a", payload);
        var pae2 = DssePae.Encode("type-b", payload);

        Assert.NotEqual(pae1, pae2);
    }

    [Fact]
    public void Encode_null_type_throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            DssePae.Encode(null!, "data"u8.ToArray()));
    }

    [Fact]
    public void Encode_null_payload_throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            DssePae.Encode("type", null!));
    }
}
