using System.Text;

namespace Sigil.Attestation;

/// <summary>
/// DSSE Pre-Authentication Encoding (PAE).
/// Encodes: "DSSEv1" + SP + len(type) + SP + type + SP + len(body) + SP + body
/// where SP = space (0x20), len = decimal ASCII length of the field.
/// </summary>
public static class DssePae
{
    public static byte[] Encode(string payloadType, byte[] payload)
    {
        ArgumentNullException.ThrowIfNull(payloadType);
        ArgumentNullException.ThrowIfNull(payload);

        var typeBytes = Encoding.UTF8.GetBytes(payloadType);

        // "DSSEv1" SP len(type) SP type SP len(body) SP body
        var prefix = Encoding.UTF8.GetBytes("DSSEv1");
        var sp = " "u8.ToArray();
        var typeLen = Encoding.UTF8.GetBytes(typeBytes.Length.ToString(System.Globalization.CultureInfo.InvariantCulture));
        var bodyLen = Encoding.UTF8.GetBytes(payload.Length.ToString(System.Globalization.CultureInfo.InvariantCulture));

        var totalLength = prefix.Length + sp.Length + typeLen.Length + sp.Length
            + typeBytes.Length + sp.Length + bodyLen.Length + sp.Length + payload.Length;

        var result = new byte[totalLength];
        var offset = 0;

        Copy(prefix, result, ref offset);
        Copy(sp, result, ref offset);
        Copy(typeLen, result, ref offset);
        Copy(sp, result, ref offset);
        Copy(typeBytes, result, ref offset);
        Copy(sp, result, ref offset);
        Copy(bodyLen, result, ref offset);
        Copy(sp, result, ref offset);
        Copy(payload, result, ref offset);

        return result;
    }

    private static void Copy(byte[] src, byte[] dst, ref int offset)
    {
        Buffer.BlockCopy(src, 0, dst, offset, src.Length);
        offset += src.Length;
    }
}
