using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;

namespace Sigil.Discovery;

/// <summary>
/// Low-level DNS TXT record client using raw UDP queries.
/// No external dependencies — uses BCL UdpClient only.
/// </summary>
public static class DnsTxtClient
{
    private const int DnsPort = 53;
    private const ushort QTypeTxt = 16;
    private const ushort QClassIn = 1;

    /// <summary>
    /// Builds a raw DNS query for TXT records.
    /// </summary>
    public static byte[] BuildQuery(string domain, ushort transactionId = 0)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);

        using var ms = new MemoryStream();

        // Transaction ID
        ms.WriteByte((byte)(transactionId >> 8));
        ms.WriteByte((byte)(transactionId & 0xFF));

        // Flags: standard query (0x0100) — recursion desired
        ms.WriteByte(0x01);
        ms.WriteByte(0x00);

        // QDCOUNT = 1
        ms.WriteByte(0x00);
        ms.WriteByte(0x01);

        // ANCOUNT = 0
        ms.WriteByte(0x00);
        ms.WriteByte(0x00);

        // NSCOUNT = 0
        ms.WriteByte(0x00);
        ms.WriteByte(0x00);

        // ARCOUNT = 0
        ms.WriteByte(0x00);
        ms.WriteByte(0x00);

        // QNAME
        var labels = domain.Split('.');
        foreach (var label in labels)
        {
            ms.WriteByte((byte)label.Length);
            var bytes = Encoding.ASCII.GetBytes(label);
            ms.Write(bytes, 0, bytes.Length);
        }
        ms.WriteByte(0x00); // root label

        // QTYPE = TXT (16)
        ms.WriteByte((byte)(QTypeTxt >> 8));
        ms.WriteByte((byte)(QTypeTxt & 0xFF));

        // QCLASS = IN (1)
        ms.WriteByte((byte)(QClassIn >> 8));
        ms.WriteByte((byte)(QClassIn & 0xFF));

        return ms.ToArray();
    }

    /// <summary>
    /// Parses TXT records from a raw DNS response.
    /// Returns an empty list if the response is malformed or contains no TXT answers.
    /// </summary>
    public static IReadOnlyList<string> ParseTxtRecords(byte[] response)
    {
        var records = new List<string>();

        if (response.Length < 12)
            return records;

        // Read answer count from header
        int answerCount = (response[6] << 8) | response[7];
        if (answerCount == 0)
            return records;

        // Skip header (12 bytes) and question section
        int offset = 12;
        offset = SkipQuestionSection(response, offset);
        if (offset < 0)
            return records;

        // Parse answer records
        for (int i = 0; i < answerCount && offset < response.Length; i++)
        {
            // Skip name (may be a pointer or labels)
            offset = SkipName(response, offset);
            if (offset < 0 || offset + 10 > response.Length)
                break;

            // TYPE (2 bytes)
            int rtype = (response[offset] << 8) | response[offset + 1];
            offset += 2;

            // CLASS (2 bytes)
            offset += 2;

            // TTL (4 bytes)
            offset += 4;

            // RDLENGTH (2 bytes)
            int rdLength = (response[offset] << 8) | response[offset + 1];
            offset += 2;

            if (offset + rdLength > response.Length)
                break;

            if (rtype == QTypeTxt)
            {
                // Parse TXT RDATA: one or more <length><text> pairs
                int rdEnd = offset + rdLength;
                var sb = new StringBuilder();
                while (offset < rdEnd)
                {
                    int txtLen = response[offset];
                    offset++;
                    if (offset + txtLen > rdEnd)
                        break;

                    if (sb.Length > 0)
                        sb.Append(' ');

                    sb.Append(Encoding.UTF8.GetString(response, offset, txtLen));
                    offset += txtLen;
                }
                if (sb.Length > 0)
                    records.Add(sb.ToString());
            }
            else
            {
                offset += rdLength;
            }
        }

        return records;
    }

    /// <summary>
    /// Queries a DNS server for TXT records of the given domain.
    /// </summary>
    public static async Task<DiscoveryResult<IReadOnlyList<string>>> QueryAsync(
        string domain,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);

        var dnsServer = GetSystemDnsServer();
        if (dnsServer is null)
        {
            return DiscoveryResult<IReadOnlyList<string>>.Fail(
                DiscoveryErrorKind.DnsError, "No DNS server found on this system.");
        }

        var txId = (ushort)(Random.Shared.Next(0, 0xFFFF));
        var query = BuildQuery(domain, txId);

        try
        {
            using var udp = new UdpClient();
            udp.Client.ReceiveTimeout = 5000;

            await udp.SendAsync(query, query.Length, new IPEndPoint(dnsServer, DnsPort))
                .ConfigureAwait(false);

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(5));

            var result = await udp.ReceiveAsync(cts.Token).ConfigureAwait(false);
            var records = ParseTxtRecords(result.Buffer);

            return DiscoveryResult<IReadOnlyList<string>>.Ok(records);
        }
        catch (OperationCanceledException)
        {
            return DiscoveryResult<IReadOnlyList<string>>.Fail(
                DiscoveryErrorKind.Timeout, $"DNS query for {domain} timed out.");
        }
        catch (SocketException ex)
        {
            return DiscoveryResult<IReadOnlyList<string>>.Fail(
                DiscoveryErrorKind.DnsError, $"DNS query failed: {ex.Message}");
        }
    }

    private static int SkipQuestionSection(byte[] data, int offset)
    {
        // Skip QDCOUNT questions (we only ever send 1)
        int qdCount = (data[4] << 8) | data[5];
        for (int i = 0; i < qdCount; i++)
        {
            offset = SkipName(data, offset);
            if (offset < 0)
                return -1;
            offset += 4; // QTYPE + QCLASS
        }
        return offset;
    }

    private static int SkipName(byte[] data, int offset)
    {
        if (offset >= data.Length)
            return -1;

        while (offset < data.Length)
        {
            byte b = data[offset];

            // Pointer (top 2 bits set)
            if ((b & 0xC0) == 0xC0)
            {
                return offset + 2;
            }

            // Root label
            if (b == 0)
            {
                return offset + 1;
            }

            // Regular label
            offset += 1 + b;
        }

        return -1;
    }

    private static IPAddress? GetSystemDnsServer()
    {
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up)
                    continue;

                var ipProps = ni.GetIPProperties();
                foreach (var dns in ipProps.DnsAddresses)
                {
                    if (dns.AddressFamily == AddressFamily.InterNetwork)
                        return dns;
                }
            }
        }
        catch
        {
            // Swallow — we'll return null and the caller handles it
        }

        return null;
    }
}
