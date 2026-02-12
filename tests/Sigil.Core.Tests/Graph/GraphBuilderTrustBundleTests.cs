using Sigil.Graph;
using Sigil.Trust;

namespace Sigil.Core.Tests.Graph;

public class GraphBuilderTrustBundleTests
{
    private static TrustBundle CreateBundle(
        List<TrustedKeyEntry>? keys = null,
        List<Endorsement>? endorsements = null,
        List<RevocationEntry>? revocations = null,
        List<TrustedIdentity>? identities = null)
    {
        return new TrustBundle
        {
            Metadata = new BundleMetadata
            {
                Name = "test-bundle",
                Created = "2026-01-01T00:00:00Z"
            },
            Keys = keys ?? [],
            Endorsements = endorsements ?? [],
            Revocations = revocations ?? [],
            Identities = identities ?? []
        };
    }

    [Fact]
    public void IngestTrustBundle_creates_key_node_for_each_entry()
    {
        var graph = new TrustGraph();
        var bundle = CreateBundle(keys:
        [
            new TrustedKeyEntry { Fingerprint = "sha256:aaa" },
            new TrustedKeyEntry { Fingerprint = "sha256:bbb" }
        ]);

        GraphBuilder.IngestTrustBundle(graph, bundle);

        Assert.NotNull(graph.TryGetNode("key:sha256:aaa"));
        Assert.NotNull(graph.TryGetNode("key:sha256:bbb"));
    }

    [Fact]
    public void IngestTrustBundle_sets_display_name_as_label()
    {
        var graph = new TrustGraph();
        var bundle = CreateBundle(keys:
        [
            new TrustedKeyEntry { Fingerprint = "sha256:named", DisplayName = "Production Key" }
        ]);

        GraphBuilder.IngestTrustBundle(graph, bundle);

        var node = graph.GetNode("key:sha256:named");
        Assert.Equal("Production Key", node.Label);
    }

    [Fact]
    public void IngestTrustBundle_uses_fingerprint_as_label_when_no_display_name()
    {
        var graph = new TrustGraph();
        var bundle = CreateBundle(keys:
        [
            new TrustedKeyEntry { Fingerprint = "sha256:unnamed" }
        ]);

        GraphBuilder.IngestTrustBundle(graph, bundle);

        var node = graph.GetNode("key:sha256:unnamed");
        Assert.Equal("sha256:unnamed", node.Label);
    }

    [Fact]
    public void IngestTrustBundle_creates_endorsed_by_edge()
    {
        var graph = new TrustGraph();
        var bundle = CreateBundle(
            keys:
            [
                new TrustedKeyEntry { Fingerprint = "sha256:endorsed" },
                new TrustedKeyEntry { Fingerprint = "sha256:endorser" }
            ],
            endorsements:
            [
                new Endorsement
                {
                    Endorsed = "sha256:endorsed",
                    Endorser = "sha256:endorser",
                    Timestamp = "2026-01-01T00:00:00Z"
                }
            ]);

        GraphBuilder.IngestTrustBundle(graph, bundle);

        var edges = graph.GetOutgoingEdges("key:sha256:endorsed");
        Assert.Single(edges);
        Assert.Equal(GraphEdgeType.EndorsedBy, edges[0].Type);
        Assert.Equal("key:sha256:endorser", edges[0].TargetId);
    }

    [Fact]
    public void IngestTrustBundle_sets_endorsement_statement_property()
    {
        var graph = new TrustGraph();
        var bundle = CreateBundle(
            keys:
            [
                new TrustedKeyEntry { Fingerprint = "sha256:e1" },
                new TrustedKeyEntry { Fingerprint = "sha256:e2" }
            ],
            endorsements:
            [
                new Endorsement
                {
                    Endorsed = "sha256:e1",
                    Endorser = "sha256:e2",
                    Statement = "Verified identity of key holder",
                    Timestamp = "2026-01-01T00:00:00Z"
                }
            ]);

        GraphBuilder.IngestTrustBundle(graph, bundle);

        var edges = graph.GetOutgoingEdges("key:sha256:e1");
        Assert.Equal("Verified identity of key holder", edges[0].Properties["statement"]);
    }

    [Fact]
    public void IngestTrustBundle_creates_revoked_at_self_loop()
    {
        var graph = new TrustGraph();
        var bundle = CreateBundle(
            keys: [new TrustedKeyEntry { Fingerprint = "sha256:revoked" }],
            revocations:
            [
                new RevocationEntry
                {
                    Fingerprint = "sha256:revoked",
                    RevokedAt = "2026-06-15T00:00:00Z"
                }
            ]);

        GraphBuilder.IngestTrustBundle(graph, bundle);

        var edges = graph.GetOutgoingEdges("key:sha256:revoked");
        Assert.Single(edges);
        Assert.Equal(GraphEdgeType.RevokedAt, edges[0].Type);
        Assert.Equal("key:sha256:revoked", edges[0].SourceId);
        Assert.Equal("key:sha256:revoked", edges[0].TargetId);
    }

    [Fact]
    public void IngestTrustBundle_sets_revocation_reason_property()
    {
        var graph = new TrustGraph();
        var bundle = CreateBundle(
            keys: [new TrustedKeyEntry { Fingerprint = "sha256:compromised" }],
            revocations:
            [
                new RevocationEntry
                {
                    Fingerprint = "sha256:compromised",
                    RevokedAt = "2026-06-15T00:00:00Z",
                    Reason = "Key compromised"
                }
            ]);

        GraphBuilder.IngestTrustBundle(graph, bundle);

        var edges = graph.GetOutgoingEdges("key:sha256:compromised");
        Assert.Equal("Key compromised", edges[0].Properties["reason"]);
    }

    [Fact]
    public void IngestTrustBundle_creates_identity_node()
    {
        var graph = new TrustGraph();
        var bundle = CreateBundle(identities:
        [
            new TrustedIdentity
            {
                Issuer = "https://accounts.google.com",
                SubjectPattern = "alice@example.com",
                DisplayName = "Alice"
            }
        ]);

        GraphBuilder.IngestTrustBundle(graph, bundle);

        var node = graph.GetNode("identity:https://accounts.google.com/alice@example.com");
        Assert.Equal(GraphNodeType.Identity, node.Type);
        Assert.Equal("Alice", node.Label);
    }

    [Fact]
    public void IngestTrustBundle_empty_bundle_adds_no_nodes()
    {
        var graph = new TrustGraph();
        var bundle = CreateBundle();

        GraphBuilder.IngestTrustBundle(graph, bundle);

        Assert.Equal(0, graph.NodeCount);
        Assert.Equal(0, graph.EdgeCount);
    }

    [Fact]
    public void IngestTrustBundle_deduplicates_key_nodes_across_bundles()
    {
        var graph = new TrustGraph();
        var bundle1 = CreateBundle(keys:
            [new TrustedKeyEntry { Fingerprint = "sha256:shared", DisplayName = "First" }]);
        var bundle2 = CreateBundle(keys:
            [new TrustedKeyEntry { Fingerprint = "sha256:shared", DisplayName = "Second" }]);

        GraphBuilder.IngestTrustBundle(graph, bundle1);
        GraphBuilder.IngestTrustBundle(graph, bundle2);

        var keyNodes = graph.AllNodes.Where(n => n.Id == "key:sha256:shared").ToList();
        Assert.Single(keyNodes);
        Assert.Equal("First", keyNodes[0].Label);
    }
}
