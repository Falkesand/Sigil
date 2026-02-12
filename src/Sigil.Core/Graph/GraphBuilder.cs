using System.Text.Json;
using Sigil.Attestation;
using Sigil.Signing;
using Sigil.Transparency;
using Sigil.Trust;

namespace Sigil.Graph;

/// <summary>
/// Ingests various Sigil data structures into a <see cref="TrustGraph"/>.
/// Each method adds nodes and edges for the given structure, using
/// first-write-wins deduplication via <see cref="TrustGraph.TryAddNode"/>.
/// </summary>
public static class GraphBuilder
{
    /// <summary>
    /// Ingests a signature envelope, creating artifact, key, identity, and log nodes
    /// with appropriate edges.
    /// </summary>
    public static void IngestSignatureEnvelope(TrustGraph graph, SignatureEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(graph);
        ArgumentNullException.ThrowIfNull(envelope);

        var artifactId = $"artifact:{envelope.Subject.Name}";
        var artifactNode = new GraphNode(artifactId, GraphNodeType.Artifact, envelope.Subject.Name);

        foreach (var kvp in envelope.Subject.Digests)
        {
            artifactNode.Properties[kvp.Key] = kvp.Value;
        }

        if (envelope.Subject.MediaType is not null)
        {
            artifactNode.Properties["mediaType"] = envelope.Subject.MediaType;
        }

        graph.TryAddNode(artifactNode);

        foreach (var entry in envelope.Signatures)
        {
            var keyId = $"key:{entry.KeyId}";
            var keyNode = new GraphNode(keyId, GraphNodeType.Key, entry.KeyId);
            keyNode.Properties["algorithm"] = entry.Algorithm;
            keyNode.Properties["publicKey"] = TruncatePublicKey(entry.PublicKey);
            graph.TryAddNode(keyNode);

            var signedByEdge = new GraphEdge(artifactId, keyId, GraphEdgeType.SignedBy, "signed by");
            graph.AddEdge(signedByEdge);

            if (entry.OidcIssuer is not null && entry.OidcIdentity is not null)
            {
                var identityId = $"identity:{entry.OidcIssuer}/{entry.OidcIdentity}";
                var identityNode = new GraphNode(identityId, GraphNodeType.Identity, entry.OidcIdentity);
                graph.TryAddNode(identityNode);

                var identityEdge = new GraphEdge(keyId, identityId, GraphEdgeType.IdentityBoundTo, "identity bound to");
                graph.AddEdge(identityEdge);
            }

            if (entry.TransparencyLogIndex is not null)
            {
                var logId = $"log:{entry.TransparencyLogIndex}";
                var logNode = new GraphNode(logId, GraphNodeType.LogRecord, $"Log #{entry.TransparencyLogIndex}");
                graph.TryAddNode(logNode);

                var logEdge = new GraphEdge(keyId, logId, GraphEdgeType.LoggedIn, "logged in");
                graph.AddEdge(logEdge);
            }
        }
    }

    /// <summary>
    /// Ingests a trust bundle, creating key, identity, endorsement, and revocation nodes/edges.
    /// </summary>
    public static void IngestTrustBundle(TrustGraph graph, TrustBundle bundle)
    {
        ArgumentNullException.ThrowIfNull(graph);
        ArgumentNullException.ThrowIfNull(bundle);

        foreach (var entry in bundle.Keys)
        {
            var keyId = $"key:{entry.Fingerprint}";
            var keyNode = new GraphNode(keyId, GraphNodeType.Key, entry.DisplayName ?? entry.Fingerprint);

            if (entry.NotAfter is not null)
            {
                keyNode.Properties["notAfter"] = entry.NotAfter;
            }

            graph.TryAddNode(keyNode);
        }

        foreach (var endorsement in bundle.Endorsements)
        {
            var endorsedId = $"key:{endorsement.Endorsed}";
            var endorserId = $"key:{endorsement.Endorser}";

            // Ensure both nodes exist (first-write-wins)
            graph.TryAddNode(new GraphNode(endorsedId, GraphNodeType.Key, endorsement.Endorsed));
            graph.TryAddNode(new GraphNode(endorserId, GraphNodeType.Key, endorsement.Endorser));

            var endorsedByEdge = new GraphEdge(endorsedId, endorserId, GraphEdgeType.EndorsedBy, "endorsed by");

            if (endorsement.Statement is not null)
            {
                endorsedByEdge.Properties["statement"] = endorsement.Statement;
            }

            if (endorsement.NotAfter is not null)
            {
                endorsedByEdge.Properties["notAfter"] = endorsement.NotAfter;
            }

            graph.AddEdge(endorsedByEdge);
        }

        foreach (var revocation in bundle.Revocations)
        {
            var keyId = $"key:{revocation.Fingerprint}";

            // Ensure node exists
            graph.TryAddNode(new GraphNode(keyId, GraphNodeType.Key, revocation.Fingerprint));

            var revokedEdge = new GraphEdge(keyId, keyId, GraphEdgeType.RevokedAt, "revoked");
            revokedEdge.Properties["revokedAt"] = revocation.RevokedAt;

            if (revocation.Reason is not null)
            {
                revokedEdge.Properties["reason"] = revocation.Reason;
            }

            graph.AddEdge(revokedEdge);
        }

        foreach (var identity in bundle.Identities)
        {
            var identityId = $"identity:{identity.Issuer}/{identity.SubjectPattern}";
            var identityNode = new GraphNode(
                identityId,
                GraphNodeType.Identity,
                identity.DisplayName ?? identity.SubjectPattern);
            graph.TryAddNode(identityNode);
        }
    }

    /// <summary>
    /// Ingests a manifest envelope, creating a root artifact node, subject artifact nodes,
    /// and key nodes with appropriate edges.
    /// </summary>
    public static void IngestManifestEnvelope(TrustGraph graph, ManifestEnvelope envelope, string manifestName)
    {
        ArgumentNullException.ThrowIfNull(graph);
        ArgumentNullException.ThrowIfNull(envelope);
        ArgumentNullException.ThrowIfNull(manifestName);

        var rootId = $"artifact:{manifestName}";
        var rootNode = new GraphNode(rootId, GraphNodeType.Artifact, manifestName);
        rootNode.Properties["kind"] = envelope.Kind;
        graph.TryAddNode(rootNode);

        foreach (var subject in envelope.Subjects)
        {
            var subjectId = $"artifact:{subject.Name}";
            var subjectNode = new GraphNode(subjectId, GraphNodeType.Artifact, subject.Name);
            graph.TryAddNode(subjectNode);

            var containedInEdge = new GraphEdge(subjectId, rootId, GraphEdgeType.ContainedIn, "contained in");
            graph.AddEdge(containedInEdge);
        }

        foreach (var entry in envelope.Signatures)
        {
            var keyId = $"key:{entry.KeyId}";
            var keyNode = new GraphNode(keyId, GraphNodeType.Key, entry.KeyId);
            keyNode.Properties["algorithm"] = entry.Algorithm;
            graph.TryAddNode(keyNode);

            var signedByEdge = new GraphEdge(rootId, keyId, GraphEdgeType.SignedBy, "signed by");
            graph.AddEdge(signedByEdge);
        }
    }

    /// <summary>
    /// Ingests a DSSE attestation envelope and its extracted in-toto statement,
    /// creating artifact, attestation, and key nodes with appropriate edges.
    /// </summary>
    public static void IngestAttestationEnvelope(TrustGraph graph, DsseEnvelope envelope, InTotoStatement statement)
    {
        ArgumentNullException.ThrowIfNull(graph);
        ArgumentNullException.ThrowIfNull(envelope);
        ArgumentNullException.ThrowIfNull(statement);

        var attestationIds = new List<string>();

        foreach (var subject in statement.Subject)
        {
            var artifactId = $"artifact:{subject.Name}";
            var artifactNode = new GraphNode(artifactId, GraphNodeType.Artifact, subject.Name);
            graph.TryAddNode(artifactNode);

            var attestationId = $"attestation:{statement.PredicateType}:{subject.Name}";
            var attestationNode = new GraphNode(
                attestationId,
                GraphNodeType.Attestation,
                $"{statement.PredicateType} for {subject.Name}");
            graph.TryAddNode(attestationNode);

            var attestedByEdge = new GraphEdge(artifactId, attestationId, GraphEdgeType.AttestedBy, "attested by");
            graph.AddEdge(attestedByEdge);

            attestationIds.Add(attestationId);
        }

        foreach (var sig in envelope.Signatures)
        {
            var keyId = $"key:{sig.KeyId}";
            var keyNode = new GraphNode(keyId, GraphNodeType.Key, sig.KeyId);
            keyNode.Properties["algorithm"] = sig.Algorithm;
            graph.TryAddNode(keyNode);

            foreach (var attestationId in attestationIds)
            {
                var signedByEdge = new GraphEdge(attestationId, keyId, GraphEdgeType.SignedBy, "signed by");
                graph.AddEdge(signedByEdge);
            }
        }
    }

    /// <summary>
    /// Ingests a transparency log entry, creating log, key, and artifact nodes with appropriate edges.
    /// </summary>
    public static void IngestLogEntry(TrustGraph graph, LogEntry entry)
    {
        ArgumentNullException.ThrowIfNull(graph);
        ArgumentNullException.ThrowIfNull(entry);

        var logId = $"log:{entry.Index}";
        var logNode = new GraphNode(logId, GraphNodeType.LogRecord, $"Log #{entry.Index}");
        logNode.Properties["timestamp"] = entry.Timestamp;
        logNode.Properties["artifactDigest"] = entry.ArtifactDigest;
        logNode.Properties["signatureDigest"] = entry.SignatureDigest;
        graph.TryAddNode(logNode);

        var keyId = $"key:{entry.KeyId}";
        var keyNode = new GraphNode(keyId, GraphNodeType.Key, entry.KeyId);
        keyNode.Properties["algorithm"] = entry.Algorithm;
        graph.TryAddNode(keyNode);

        var loggedInEdge = new GraphEdge(keyId, logId, GraphEdgeType.LoggedIn, "logged in");
        graph.AddEdge(loggedInEdge);

        var artifactId = $"artifact:{entry.ArtifactName}";
        var artifactNode = new GraphNode(artifactId, GraphNodeType.Artifact, entry.ArtifactName);
        graph.TryAddNode(artifactNode);

        var signedByEdge = new GraphEdge(artifactId, keyId, GraphEdgeType.SignedBy, "signed by");
        graph.AddEdge(signedByEdge);
    }

    /// <summary>
    /// Scans a directory for Sigil signature, manifest, attestation, and trust bundle files,
    /// ingesting each into the graph. Per-file errors are caught and skipped.
    /// </summary>
    public static GraphResult<int> ScanDirectory(TrustGraph graph, string directoryPath)
    {
        ArgumentNullException.ThrowIfNull(graph);
        ArgumentNullException.ThrowIfNull(directoryPath);

        if (!Directory.Exists(directoryPath))
        {
            return GraphResult<int>.Fail(GraphErrorKind.FileNotFound, $"Directory not found: {directoryPath}");
        }

        var count = 0;

        // Signature envelopes: *.sig.json (excluding manifest and archive variants)
        var sigFiles = Directory.GetFiles(directoryPath, "*.sig.json", SearchOption.TopDirectoryOnly);
        foreach (var file in sigFiles)
        {
            var fileName = Path.GetFileName(file);
            if (fileName.EndsWith(".manifest.sig.json", StringComparison.OrdinalIgnoreCase) ||
                fileName.EndsWith(".archive.sig.json", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            try
            {
                var json = File.ReadAllText(file);
                var envelope = ArtifactSigner.Deserialize(json);
                IngestSignatureEnvelope(graph, envelope);
                count++;
            }
#pragma warning disable CA1031 // Do not catch general exception types — ScanDirectory skips per-file errors by design
            catch
#pragma warning restore CA1031
            {
                // Skip per-file errors and continue scanning
            }
        }

        // Manifest envelopes: *.manifest.sig.json
        var manifestFiles = Directory.GetFiles(directoryPath, "*.manifest.sig.json", SearchOption.TopDirectoryOnly);
        foreach (var file in manifestFiles)
        {
            try
            {
                var json = File.ReadAllText(file);
                var envelope = ManifestSigner.Deserialize(json);
                IngestManifestEnvelope(graph, envelope, Path.GetFileName(file));
                count++;
            }
#pragma warning disable CA1031
            catch
#pragma warning restore CA1031
            {
                // Skip per-file errors and continue scanning
            }
        }

        // Archive envelopes: *.archive.sig.json
        var archiveFiles = Directory.GetFiles(directoryPath, "*.archive.sig.json", SearchOption.TopDirectoryOnly);
        foreach (var file in archiveFiles)
        {
            try
            {
                var json = File.ReadAllText(file);
                var envelope = ManifestSigner.Deserialize(json);
                IngestManifestEnvelope(graph, envelope, Path.GetFileName(file));
                count++;
            }
#pragma warning disable CA1031
            catch
#pragma warning restore CA1031
            {
                // Skip per-file errors and continue scanning
            }
        }

        // Attestation envelopes: *.att.json
        var attFiles = Directory.GetFiles(directoryPath, "*.att.json", SearchOption.TopDirectoryOnly);
        foreach (var file in attFiles)
        {
            try
            {
                var json = File.ReadAllText(file);
                var deserializeResult = AttestationCreator.Deserialize(json);
                if (!deserializeResult.IsSuccess)
                {
                    continue;
                }

                var extractResult = AttestationCreator.ExtractStatement(deserializeResult.Value);
                if (!extractResult.IsSuccess)
                {
                    continue;
                }

                IngestAttestationEnvelope(graph, deserializeResult.Value, extractResult.Value);
                count++;
            }
#pragma warning disable CA1031
            catch
#pragma warning restore CA1031
            {
                // Skip per-file errors and continue scanning
            }
        }

        // Trust bundles: trust.json
        var trustFiles = Directory.GetFiles(directoryPath, "trust.json", SearchOption.TopDirectoryOnly);
        foreach (var file in trustFiles)
        {
            try
            {
                var json = File.ReadAllText(file);
                var result = BundleSigner.Deserialize(json);
                if (!result.IsSuccess)
                {
                    continue;
                }

                IngestTrustBundle(graph, result.Value);
                count++;
            }
#pragma warning disable CA1031
            catch
#pragma warning restore CA1031
            {
                // Skip per-file errors and continue scanning
            }
        }

        return GraphResult<int>.Ok(count);
    }

    private static string TruncatePublicKey(string publicKey)
    {
        return publicKey.Length > 16
            ? string.Concat(publicKey.AsSpan(0, 16), "...")
            : publicKey;
    }
}
