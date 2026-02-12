using Sigil.Graph;
using Sigil.Transparency;

namespace Sigil.Core.Tests.Graph;

public class GraphBuilderLogEntryTests
{
    private static LogEntry CreateLogEntry(
        long index = 1,
        string keyId = "sha256:logkey",
        string algorithm = "ecdsa-p256",
        string artifactName = "test.dll",
        string timestamp = "2026-01-15T12:00:00Z")
    {
        return new LogEntry
        {
            Index = index,
            Timestamp = timestamp,
            KeyId = keyId,
            Algorithm = algorithm,
            ArtifactName = artifactName,
            ArtifactDigest = "sha256:artifactdigest",
            SignatureDigest = "sha256:sigdigest",
            LeafHash = "sha256:leafhash"
        };
    }

    [Fact]
    public void IngestLogEntry_creates_log_record_node()
    {
        var graph = new TrustGraph();
        var entry = CreateLogEntry(index: 99);

        GraphBuilder.IngestLogEntry(graph, entry);

        var node = graph.GetNode("log:99");
        Assert.Equal(GraphNodeType.LogRecord, node.Type);
        Assert.Equal("Log #99", node.Label);
    }

    [Fact]
    public void IngestLogEntry_creates_key_node()
    {
        var graph = new TrustGraph();
        var entry = CreateLogEntry(keyId: "sha256:transparency-key", algorithm: "ecdsa-p384");

        GraphBuilder.IngestLogEntry(graph, entry);

        var node = graph.GetNode("key:sha256:transparency-key");
        Assert.Equal(GraphNodeType.Key, node.Type);
        Assert.Equal("ecdsa-p384", node.Properties["algorithm"]);
    }

    [Fact]
    public void IngestLogEntry_creates_logged_in_edge()
    {
        var graph = new TrustGraph();
        var entry = CreateLogEntry(index: 5, keyId: "sha256:lk");

        GraphBuilder.IngestLogEntry(graph, entry);

        var edges = graph.GetOutgoingEdges("key:sha256:lk");
        Assert.Single(edges);
        Assert.Equal(GraphEdgeType.LoggedIn, edges[0].Type);
        Assert.Equal("log:5", edges[0].TargetId);
    }

    [Fact]
    public void IngestLogEntry_creates_artifact_node()
    {
        var graph = new TrustGraph();
        var entry = CreateLogEntry(artifactName: "release.zip");

        GraphBuilder.IngestLogEntry(graph, entry);

        var node = graph.GetNode("artifact:release.zip");
        Assert.Equal(GraphNodeType.Artifact, node.Type);
        Assert.Equal("release.zip", node.Label);
    }

    [Fact]
    public void IngestLogEntry_sets_timestamp_property_on_log_node()
    {
        var graph = new TrustGraph();
        var entry = CreateLogEntry(index: 10, timestamp: "2026-06-15T08:30:00Z");

        GraphBuilder.IngestLogEntry(graph, entry);

        var node = graph.GetNode("log:10");
        Assert.Equal("2026-06-15T08:30:00Z", node.Properties["timestamp"]);
    }

    [Fact]
    public void IngestLogEntry_creates_signed_by_edge_from_artifact_to_key()
    {
        var graph = new TrustGraph();
        var entry = CreateLogEntry(artifactName: "signed.exe", keyId: "sha256:signer");

        GraphBuilder.IngestLogEntry(graph, entry);

        var edges = graph.GetOutgoingEdges("artifact:signed.exe");
        Assert.Single(edges);
        Assert.Equal(GraphEdgeType.SignedBy, edges[0].Type);
        Assert.Equal("key:sha256:signer", edges[0].TargetId);
    }
}
