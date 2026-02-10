using System.Text.Json;

namespace Sigil.Transparency.Remote;

public static class RekorEntryParser
{
    public static RemoteLogResult<TransparencyReceipt> ParseResponse(
        string json, string logUrl)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);
        ArgumentException.ThrowIfNullOrWhiteSpace(logUrl);

        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            // Rekor response is a dict keyed by UUID
            if (root.ValueKind != JsonValueKind.Object)
            {
                return RemoteLogResult<TransparencyReceipt>.Fail(
                    RemoteLogErrorKind.InvalidResponse, "Rekor response is not a JSON object.");
            }

            // Get the first (and only) entry by UUID
            JsonElement entry = default;
            string? uuid = null;
            foreach (var prop in root.EnumerateObject())
            {
                uuid = prop.Name;
                entry = prop.Value;
                break;
            }

            if (uuid is null)
            {
                return RemoteLogResult<TransparencyReceipt>.Fail(
                    RemoteLogErrorKind.InvalidResponse, "Rekor response contains no entries.");
            }

            // Extract logIndex
            if (!entry.TryGetProperty("logIndex", out var logIndexElement) ||
                !logIndexElement.TryGetInt64(out var logIndex))
            {
                return RemoteLogResult<TransparencyReceipt>.Fail(
                    RemoteLogErrorKind.InvalidResponse, "Rekor entry missing 'logIndex'.");
            }

            // Extract verification object
            string signedCheckpoint;
            if (entry.TryGetProperty("verification", out var verification) &&
                verification.TryGetProperty("signedEntryTimestamp", out var setElement) &&
                setElement.GetString() is { } set)
            {
                signedCheckpoint = set;
            }
            else
            {
                signedCheckpoint = "";
            }

            // Extract inclusion proof if available
            RemoteInclusionProof? inclusionProof = null;
            if (entry.TryGetProperty("verification", out var verif2) &&
                verif2.TryGetProperty("inclusionProof", out var proofElement))
            {
                var leafIndex = proofElement.TryGetProperty("logIndex", out var li) && li.TryGetInt64(out var liVal) ? liVal : logIndex;
                var treeSize = proofElement.TryGetProperty("treeSize", out var ts) && ts.TryGetInt64(out var tsVal) ? tsVal : 0;
                var rootHash = proofElement.TryGetProperty("rootHash", out var rh) ? rh.GetString() ?? "" : "";
                var hashes = new List<string>();
                if (proofElement.TryGetProperty("hashes", out var hashesElement) &&
                    hashesElement.ValueKind == JsonValueKind.Array)
                {
                    foreach (var h in hashesElement.EnumerateArray())
                    {
                        if (h.GetString() is { } hashStr)
                            hashes.Add(hashStr);
                    }
                }

                inclusionProof = new RemoteInclusionProof
                {
                    LeafIndex = leafIndex,
                    TreeSize = treeSize,
                    RootHash = rootHash,
                    Hashes = hashes
                };
            }

            inclusionProof ??= new RemoteInclusionProof
            {
                LeafIndex = logIndex,
                TreeSize = 0,
                RootHash = "",
                Hashes = []
            };

            var receipt = new TransparencyReceipt
            {
                LogUrl = logUrl,
                LogIndex = logIndex,
                SignedCheckpoint = signedCheckpoint,
                InclusionProof = inclusionProof
            };

            return RemoteLogResult<TransparencyReceipt>.Ok(receipt);
        }
        catch (JsonException ex)
        {
            return RemoteLogResult<TransparencyReceipt>.Fail(
                RemoteLogErrorKind.InvalidResponse, $"Failed to parse Rekor response: {ex.Message}");
        }
    }

    public static string SpkiToPem(string base64Spki)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(base64Spki);

        var sb = new System.Text.StringBuilder();
        sb.AppendLine("-----BEGIN PUBLIC KEY-----");

        // Wrap base64 at 64 chars per line
        for (int i = 0; i < base64Spki.Length; i += 64)
        {
            var lineLength = Math.Min(64, base64Spki.Length - i);
            sb.AppendLine(base64Spki[i..(i + lineLength)]);
        }

        sb.AppendLine("-----END PUBLIC KEY-----");
        return sb.ToString();
    }
}
