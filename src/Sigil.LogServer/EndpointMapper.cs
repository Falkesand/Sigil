using System.Text.Json;
using Sigil.LogServer.Storage;

namespace Sigil.LogServer;

public static class EndpointMapper
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    public static void Map(WebApplication app, LogService logService, ILogStore store, ICheckpointSigner signer)
    {
        app.MapPost("/api/v1/log/entries", async (HttpContext ctx) =>
        {
            AppendRequest? request;
            try
            {
                request = await JsonSerializer.DeserializeAsync<AppendRequest>(ctx.Request.Body, JsonOptions);
            }
            catch (JsonException)
            {
                ctx.Response.StatusCode = 400;
                await ctx.Response.WriteAsJsonAsync(new { error = "Invalid JSON." });
                return;
            }

            if (request is null ||
                string.IsNullOrWhiteSpace(request.KeyId) ||
                string.IsNullOrWhiteSpace(request.Algorithm) ||
                string.IsNullOrWhiteSpace(request.PublicKey) ||
                string.IsNullOrWhiteSpace(request.SignatureValue) ||
                string.IsNullOrWhiteSpace(request.ArtifactName) ||
                string.IsNullOrWhiteSpace(request.ArtifactDigest))
            {
                ctx.Response.StatusCode = 400;
                await ctx.Response.WriteAsJsonAsync(new { error = "Missing required fields." });
                return;
            }

            if (!ValidateAppendRequest(request, out var validationError))
            {
                ctx.Response.StatusCode = 400;
                await ctx.Response.WriteAsJsonAsync(new { error = validationError });
                return;
            }

            var result = await logService.AppendAsync(request);

            if (result.IsDuplicate)
            {
                ctx.Response.StatusCode = 409;
                await ctx.Response.WriteAsJsonAsync(new { error = "Entry already exists." });
                return;
            }

            if (!result.IsSuccess)
            {
                ctx.Response.StatusCode = 500;
                await ctx.Response.WriteAsJsonAsync(new { error = "Failed to append entry." });
                return;
            }

            ctx.Response.StatusCode = 201;
            await ctx.Response.WriteAsJsonAsync(new
            {
                logIndex = result.LogIndex,
                leafHash = result.LeafHash,
                signedCheckpoint = result.SignedCheckpoint,
                inclusionProof = new
                {
                    leafIndex = result.InclusionProof!.LeafIndex,
                    treeSize = result.InclusionProof.TreeSize,
                    rootHash = result.InclusionProof.RootHash,
                    hashes = result.InclusionProof.Hashes
                }
            });
        });

        app.MapGet("/api/v1/log/entries", async (HttpContext ctx) =>
        {
            var limit = int.TryParse(ctx.Request.Query["limit"], out var l) ? Math.Clamp(l, 1, 1000) : 50;
            var offset = int.TryParse(ctx.Request.Query["offset"], out var o) ? Math.Max(o, 0) : 0;
            var entries = await store.ListEntriesAsync(limit, offset);
            var total = await store.GetEntryCountAsync();
            await ctx.Response.WriteAsJsonAsync(new { total, entries = entries.Select(MapEntry) });
        });

        app.MapGet("/api/v1/log/entries/{index:long}", async (long index, HttpContext ctx) =>
        {
            var entry = await store.GetEntryAsync(index);
            if (entry is null)
            {
                ctx.Response.StatusCode = 404;
                await ctx.Response.WriteAsJsonAsync(new { error = "Entry not found." });
                return;
            }
            await ctx.Response.WriteAsJsonAsync(MapEntry(entry));
        });

        app.MapPost("/api/v1/log/search", async (HttpContext ctx) =>
        {
            LogSearchQuery? query;
            try
            {
                query = await JsonSerializer.DeserializeAsync<LogSearchQuery>(ctx.Request.Body, JsonOptions);
            }
            catch (JsonException)
            {
                ctx.Response.StatusCode = 400;
                await ctx.Response.WriteAsJsonAsync(new { error = "Invalid JSON." });
                return;
            }
            query ??= new LogSearchQuery();
            query.Limit = Math.Clamp(query.Limit, 1, 1000);
            query.Offset = Math.Max(query.Offset, 0);
            var entries = await store.SearchAsync(query);
            await ctx.Response.WriteAsJsonAsync(new { entries = entries.Select(MapEntry) });
        });

        app.MapGet("/api/v1/log/checkpoint", async (HttpContext ctx) =>
        {
            var checkpoint = await store.GetLatestCheckpointAsync();
            if (checkpoint is null)
            {
                await ctx.Response.WriteAsJsonAsync(new
                {
                    treeSize = 0,
                    rootHash = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData([])),
                    timestamp = DateTime.UtcNow.ToString("o"),
                    signature = ""
                });
                return;
            }
            await ctx.Response.WriteAsJsonAsync(new
            {
                treeSize = checkpoint.TreeSize,
                rootHash = checkpoint.RootHash,
                timestamp = checkpoint.Timestamp,
                signature = checkpoint.Signature
            });
        });

        app.MapGet("/api/v1/log/proof/inclusion/{index:long}", async (long index, HttpContext ctx) =>
        {
            var proof = await logService.GetInclusionProofAsync(index);
            if (proof is null)
            {
                ctx.Response.StatusCode = 404;
                await ctx.Response.WriteAsJsonAsync(new { error = "Invalid leaf index." });
                return;
            }
            await ctx.Response.WriteAsJsonAsync(new
            {
                leafIndex = proof.LeafIndex,
                treeSize = proof.TreeSize,
                rootHash = proof.RootHash,
                hashes = proof.Hashes
            });
        });

        app.MapGet("/api/v1/log/proof/consistency", async (HttpContext ctx) =>
        {
            if (!long.TryParse(ctx.Request.Query["oldSize"], out var oldSize))
            {
                ctx.Response.StatusCode = 400;
                await ctx.Response.WriteAsJsonAsync(new { error = "Missing or invalid 'oldSize' parameter." });
                return;
            }
            var proof = await logService.GetConsistencyProofAsync(oldSize);
            if (proof is null)
            {
                ctx.Response.StatusCode = 400;
                await ctx.Response.WriteAsJsonAsync(new { error = "Invalid oldSize." });
                return;
            }
            await ctx.Response.WriteAsJsonAsync(new
            {
                oldSize = proof.OldSize,
                newSize = proof.NewSize,
                oldRootHash = proof.OldRootHash,
                newRootHash = proof.NewRootHash,
                hashes = proof.Hashes
            });
        });

        app.MapGet("/api/v1/log/publicKey", (HttpContext ctx) =>
        {
            ctx.Response.ContentType = "text/plain";
            return ctx.Response.WriteAsync(signer.PublicKeyBase64);
        });
    }

    private static object MapEntry(LogStoreEntry entry)
    {
        return new
        {
            index = entry.Id,
            timestamp = entry.Timestamp,
            keyId = entry.KeyId,
            algorithm = entry.Algorithm,
            artifactName = entry.ArtifactName,
            artifactDigest = entry.ArtifactDigest,
            signatureDigest = entry.SignatureDigest,
            label = entry.Label,
            leafHash = entry.LeafHash
        };
    }

    private static readonly HashSet<string> ValidAlgorithms = new(StringComparer.OrdinalIgnoreCase)
    {
        "ecdsa-p256", "ecdsa-p384", "ecdsa-p521", "rsa-pss-sha256", "ml-dsa-65", "ed25519"
    };

    private static bool ValidateAppendRequest(AppendRequest request, [System.Diagnostics.CodeAnalysis.NotNullWhen(false)] out string? error)
    {
        if (request.KeyId.Length > 200)
        {
            error = "KeyId exceeds maximum length.";
            return false;
        }
        if (request.Algorithm.Length > 50)
        {
            error = "Algorithm exceeds maximum length.";
            return false;
        }
        if (request.ArtifactName.Length > 500)
        {
            error = "ArtifactName exceeds maximum length.";
            return false;
        }
        if (request.ArtifactDigest.Length > 200)
        {
            error = "ArtifactDigest exceeds maximum length.";
            return false;
        }
        if (request.Label is not null && request.Label.Length > 200)
        {
            error = "Label exceeds maximum length.";
            return false;
        }
        if (!ValidAlgorithms.Contains(request.Algorithm))
        {
            error = $"Unsupported algorithm: {request.Algorithm}";
            return false;
        }
        if (!IsValidBase64(request.PublicKey))
        {
            error = "PublicKey is not valid base64.";
            return false;
        }
        if (!IsValidBase64(request.SignatureValue))
        {
            error = "SignatureValue is not valid base64.";
            return false;
        }

        error = null;
        return true;
    }

    private static bool IsValidBase64(string value)
    {
        Span<byte> buffer = stackalloc byte[4096];
        return Convert.TryFromBase64String(value, buffer, out _) ||
               Convert.TryFromBase64String(value, new byte[value.Length], out _);
    }
}
