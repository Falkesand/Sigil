using Sigil.Discovery;

namespace Sigil.Core.Tests.Discovery;

public class DnsTxtClientTests
{
    [Fact]
    public void BuildQuery_creates_valid_dns_txt_query()
    {
        var query = DnsTxtClient.BuildQuery("_sigil.example.com", transactionId: 0x1234);

        // Transaction ID
        Assert.Equal(0x12, query[0]);
        Assert.Equal(0x34, query[1]);

        // Flags: standard query, recursion desired
        Assert.Equal(0x01, query[2]);
        Assert.Equal(0x00, query[3]);

        // QDCOUNT = 1
        Assert.Equal(0x00, query[4]);
        Assert.Equal(0x01, query[5]);

        // ANCOUNT, NSCOUNT, ARCOUNT = 0
        for (int i = 6; i < 12; i++)
            Assert.Equal(0x00, query[i]);

        // QNAME: labels "_sigil", "example", "com" each preceded by length byte, ending with 0x00
        Assert.Equal(6, query[12]); // length of "_sigil"
        Assert.Equal((byte)'_', query[13]);
        Assert.Equal((byte)'s', query[14]);
        Assert.Equal((byte)'i', query[15]);
        Assert.Equal((byte)'g', query[16]);
        Assert.Equal((byte)'i', query[17]);
        Assert.Equal((byte)'l', query[18]);

        Assert.Equal(7, query[19]); // length of "example"

        // QTYPE = TXT (16)
        var qtypeOffset = query.Length - 4;
        Assert.Equal(0x00, query[qtypeOffset]);
        Assert.Equal(0x10, query[qtypeOffset + 1]);

        // QCLASS = IN (1)
        Assert.Equal(0x00, query[qtypeOffset + 2]);
        Assert.Equal(0x01, query[qtypeOffset + 3]);
    }

    [Fact]
    public void ParseTxtRecords_parses_valid_response()
    {
        // Build a minimal DNS response with one TXT record
        var response = BuildTxtResponse(
            transactionId: 0x1234,
            domain: "_sigil.example.com",
            txtData: "v=sigil1 bundle=https://example.com/.well-known/sigil/trust.json");

        var records = DnsTxtClient.ParseTxtRecords(response);

        Assert.Single(records);
        Assert.Equal("v=sigil1 bundle=https://example.com/.well-known/sigil/trust.json", records[0]);
    }

    [Fact]
    public void ParseTxtRecords_handles_multiple_records()
    {
        var response = BuildTxtResponse(
            transactionId: 0x5678,
            domain: "_sigil.example.com",
            txtData: "v=sigil1 bundle=https://example.com/trust.json",
            additionalTxt: "extra=data");

        var records = DnsTxtClient.ParseTxtRecords(response);

        Assert.Equal(2, records.Count);
    }

    [Fact]
    public void ParseTxtRecords_returns_empty_for_no_answers()
    {
        // A response with ANCOUNT = 0
        var response = BuildTxtResponse(
            transactionId: 0x1234,
            domain: "_sigil.example.com",
            txtData: null);

        var records = DnsTxtClient.ParseTxtRecords(response);

        Assert.Empty(records);
    }

    [Fact]
    public void ParseTxtRecords_returns_empty_for_truncated_data()
    {
        var records = DnsTxtClient.ParseTxtRecords(new byte[] { 0x12, 0x34 });

        Assert.Empty(records);
    }

    /// <summary>
    /// Builds a minimal DNS TXT response for testing.
    /// </summary>
    private static byte[] BuildTxtResponse(ushort transactionId, string domain, string? txtData, string? additionalTxt = null)
    {
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);

        // Header
        writer.Write((byte)(transactionId >> 8));
        writer.Write((byte)(transactionId & 0xFF));

        // Flags: response, recursion available
        writer.Write((byte)0x81);
        writer.Write((byte)0x80);

        // QDCOUNT = 1
        writer.Write((byte)0x00);
        writer.Write((byte)0x01);

        // ANCOUNT
        int answerCount = txtData is null ? 0 : (additionalTxt is null ? 1 : 2);
        writer.Write((byte)0x00);
        writer.Write((byte)answerCount);

        // NSCOUNT, ARCOUNT = 0
        writer.Write((byte)0x00);
        writer.Write((byte)0x00);
        writer.Write((byte)0x00);
        writer.Write((byte)0x00);

        // Question section: domain name
        WriteDnsName(writer, domain);

        // QTYPE = TXT (16), QCLASS = IN (1)
        writer.Write((byte)0x00);
        writer.Write((byte)0x10);
        writer.Write((byte)0x00);
        writer.Write((byte)0x01);

        // Answer section
        if (txtData is not null)
        {
            WriteTxtAnswer(writer, domain, txtData);
            if (additionalTxt is not null)
            {
                WriteTxtAnswer(writer, domain, additionalTxt);
            }
        }

        return ms.ToArray();
    }

    private static void WriteTxtAnswer(BinaryWriter writer, string domain, string txtData)
    {
        // Name: use pointer to question section (0xC0 0x0C)
        writer.Write((byte)0xC0);
        writer.Write((byte)0x0C);

        // TYPE = TXT (16)
        writer.Write((byte)0x00);
        writer.Write((byte)0x10);

        // CLASS = IN (1)
        writer.Write((byte)0x00);
        writer.Write((byte)0x01);

        // TTL
        writer.Write((byte)0x00);
        writer.Write((byte)0x00);
        writer.Write((byte)0x01);
        writer.Write((byte)0x2C);

        // RDLENGTH = 1 (txt length byte) + txtData.Length
        var rdLength = (ushort)(1 + txtData.Length);
        writer.Write((byte)(rdLength >> 8));
        writer.Write((byte)(rdLength & 0xFF));

        // TXT RDATA: length byte + text
        writer.Write((byte)txtData.Length);
        writer.Write(System.Text.Encoding.ASCII.GetBytes(txtData));
    }

    private static void WriteDnsName(BinaryWriter writer, string domain)
    {
        var labels = domain.Split('.');
        foreach (var label in labels)
        {
            writer.Write((byte)label.Length);
            writer.Write(System.Text.Encoding.ASCII.GetBytes(label));
        }
        writer.Write((byte)0x00); // root label
    }
}
