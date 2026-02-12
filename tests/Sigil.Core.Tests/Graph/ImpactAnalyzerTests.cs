using Sigil.Graph;

namespace Sigil.Core.Tests.Graph;

public class ImpactAnalyzerTests
{
    [Fact]
    public void Analyze_key_not_found_returns_error()
    {
        var graph = new TrustGraph();

        var result = ImpactAnalyzer.Analyze(graph, "key:sha256:missing");

        Assert.False(result.IsSuccess);
        Assert.Equal(GraphErrorKind.NodeNotFound, result.ErrorKind);
        Assert.Contains("missing", result.ErrorMessage);
    }

    [Fact]
    public void Analyze_key_with_no_signatures_returns_empty_report()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("key:sha256:lonely", GraphNodeType.Key, "lonely-key"));

        var result = ImpactAnalyzer.Analyze(graph, "key:sha256:lonely");

        Assert.True(result.IsSuccess);
        var report = result.Value;
        Assert.Equal("key:sha256:lonely", report.KeyId);
        Assert.Equal("sha256:lonely", report.Fingerprint);
        Assert.Equal("lonely-key", report.KeyLabel);
        Assert.False(report.IsRevoked);
        Assert.Empty(report.DirectArtifacts);
        Assert.Empty(report.TransitiveArtifacts);
        Assert.Empty(report.EndorsedKeys);
        Assert.Empty(report.EndorsedByKeys);
        Assert.Empty(report.BoundIdentities);
    }

    [Fact]
    public void Analyze_key_with_direct_artifacts_only()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("artifact:app.dll", GraphNodeType.Artifact, "app.dll"));
        graph.AddNode(new GraphNode("artifact:lib.dll", GraphNodeType.Artifact, "lib.dll"));
        graph.AddNode(new GraphNode("key:sha256:k1", GraphNodeType.Key, "production-key"));
        graph.AddEdge(new GraphEdge("artifact:app.dll", "key:sha256:k1", GraphEdgeType.SignedBy, "signed by"));
        graph.AddEdge(new GraphEdge("artifact:lib.dll", "key:sha256:k1", GraphEdgeType.SignedBy, "signed by"));

        var result = ImpactAnalyzer.Analyze(graph, "key:sha256:k1");

        Assert.True(result.IsSuccess);
        var report = result.Value;
        Assert.Equal(2, report.DirectArtifacts.Count);
        Assert.Contains("artifact:app.dll", report.DirectArtifacts);
        Assert.Contains("artifact:lib.dll", report.DirectArtifacts);
        Assert.Empty(report.TransitiveArtifacts);
    }

    [Fact]
    public void Analyze_key_with_endorsement_chain()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("artifact:downstream.dll", GraphNodeType.Artifact, "downstream.dll"));
        graph.AddNode(new GraphNode("key:sha256:k1", GraphNodeType.Key, "root-key"));
        graph.AddNode(new GraphNode("key:sha256:k2", GraphNodeType.Key, "child-key"));
        // K2 endorsed by K1 (K2 depends on K1)
        graph.AddEdge(new GraphEdge("key:sha256:k2", "key:sha256:k1", GraphEdgeType.EndorsedBy, "endorsed by"));
        // Artifact signed by K2
        graph.AddEdge(new GraphEdge("artifact:downstream.dll", "key:sha256:k2", GraphEdgeType.SignedBy, "signed by"));

        var result = ImpactAnalyzer.Analyze(graph, "key:sha256:k1");

        Assert.True(result.IsSuccess);
        var report = result.Value;
        Assert.Empty(report.DirectArtifacts);
        Assert.Single(report.TransitiveArtifacts);
        Assert.Equal("artifact:downstream.dll", report.TransitiveArtifacts[0]);
        Assert.Single(report.EndorsedKeys);
        Assert.Equal("key:sha256:k2", report.EndorsedKeys[0]);
    }

    [Fact]
    public void Analyze_revoked_key_shows_details()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("key:sha256:k1", GraphNodeType.Key, "compromised-key"));
        var revokedEdge = new GraphEdge("key:sha256:k1", "key:sha256:k1", GraphEdgeType.RevokedAt, "revoked");
        revokedEdge.Properties["revokedAt"] = "2026-01-15T00:00:00Z";
        revokedEdge.Properties["reason"] = "key leaked";
        graph.AddEdge(revokedEdge);

        var result = ImpactAnalyzer.Analyze(graph, "key:sha256:k1");

        Assert.True(result.IsSuccess);
        var report = result.Value;
        Assert.True(report.IsRevoked);
        Assert.Equal("2026-01-15T00:00:00Z", report.RevokedAt);
        Assert.Equal("key leaked", report.RevocationReason);
    }

    [Fact]
    public void Analyze_not_revoked_key_recommends_revocation()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("key:sha256:k1", GraphNodeType.Key, "active-key"));

        var result = ImpactAnalyzer.Analyze(graph, "key:sha256:k1");

        Assert.True(result.IsSuccess);
        var report = result.Value;
        Assert.False(report.IsRevoked);
        Assert.Contains(report.Recommendations, r => r.Contains("Revoke this key"));
    }

    [Fact]
    public void Analyze_revoked_key_does_not_recommend_revocation()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("key:sha256:k1", GraphNodeType.Key, "sha256:k1"));
        var revokedEdge = new GraphEdge("key:sha256:k1", "key:sha256:k1", GraphEdgeType.RevokedAt, "revoked");
        revokedEdge.Properties["revokedAt"] = "2026-01-15T00:00:00Z";
        graph.AddEdge(revokedEdge);

        var result = ImpactAnalyzer.Analyze(graph, "key:sha256:k1");

        Assert.True(result.IsSuccess);
        var report = result.Value;
        Assert.DoesNotContain(report.Recommendations, r => r.Contains("Revoke this key"));
    }

    [Fact]
    public void Analyze_key_with_oidc_identity_binding()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("key:sha256:k1", GraphNodeType.Key, "oidc-key"));
        graph.AddNode(new GraphNode("identity:github.com/myorg/myrepo", GraphNodeType.Identity, "myorg/myrepo"));
        graph.AddEdge(new GraphEdge("key:sha256:k1", "identity:github.com/myorg/myrepo", GraphEdgeType.IdentityBoundTo, "identity bound to"));

        var result = ImpactAnalyzer.Analyze(graph, "key:sha256:k1");

        Assert.True(result.IsSuccess);
        var report = result.Value;
        Assert.Single(report.BoundIdentities);
        Assert.Equal("identity:github.com/myorg/myrepo", report.BoundIdentities[0]);
    }

    [Fact]
    public void Analyze_key_endorsing_multiple_downstream_keys()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("key:sha256:root", GraphNodeType.Key, "root"));
        graph.AddNode(new GraphNode("key:sha256:child1", GraphNodeType.Key, "child1"));
        graph.AddNode(new GraphNode("key:sha256:child2", GraphNodeType.Key, "child2"));
        graph.AddEdge(new GraphEdge("key:sha256:child1", "key:sha256:root", GraphEdgeType.EndorsedBy, "endorsed by"));
        graph.AddEdge(new GraphEdge("key:sha256:child2", "key:sha256:root", GraphEdgeType.EndorsedBy, "endorsed by"));

        var result = ImpactAnalyzer.Analyze(graph, "key:sha256:root");

        Assert.True(result.IsSuccess);
        var report = result.Value;
        Assert.Equal(2, report.EndorsedKeys.Count);
        Assert.Contains("key:sha256:child1", report.EndorsedKeys);
        Assert.Contains("key:sha256:child2", report.EndorsedKeys);
    }

    [Fact]
    public void Analyze_key_endorsed_by_upstream_keys()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("key:sha256:k1", GraphNodeType.Key, "sha256:k1"));
        graph.AddNode(new GraphNode("key:sha256:root1", GraphNodeType.Key, "root1"));
        graph.AddNode(new GraphNode("key:sha256:root2", GraphNodeType.Key, "root2"));
        // K1 endorsed by root1 and root2
        graph.AddEdge(new GraphEdge("key:sha256:k1", "key:sha256:root1", GraphEdgeType.EndorsedBy, "endorsed by"));
        graph.AddEdge(new GraphEdge("key:sha256:k1", "key:sha256:root2", GraphEdgeType.EndorsedBy, "endorsed by"));

        var result = ImpactAnalyzer.Analyze(graph, "key:sha256:k1");

        Assert.True(result.IsSuccess);
        var report = result.Value;
        Assert.Equal(2, report.EndorsedByKeys.Count);
        Assert.Contains("key:sha256:root1", report.EndorsedByKeys);
        Assert.Contains("key:sha256:root2", report.EndorsedByKeys);
    }

    [Fact]
    public void Analyze_mixed_scenario_direct_and_transitive_and_identities()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("artifact:direct.dll", GraphNodeType.Artifact, "direct.dll"));
        graph.AddNode(new GraphNode("artifact:transitive.dll", GraphNodeType.Artifact, "transitive.dll"));
        graph.AddNode(new GraphNode("key:sha256:k1", GraphNodeType.Key, "main-key"));
        graph.AddNode(new GraphNode("key:sha256:k2", GraphNodeType.Key, "child-key"));
        graph.AddNode(new GraphNode("identity:github.com/org", GraphNodeType.Identity, "org"));

        // Direct: artifact signed by k1
        graph.AddEdge(new GraphEdge("artifact:direct.dll", "key:sha256:k1", GraphEdgeType.SignedBy, "signed by"));
        // Endorsement: k2 endorsed by k1
        graph.AddEdge(new GraphEdge("key:sha256:k2", "key:sha256:k1", GraphEdgeType.EndorsedBy, "endorsed by"));
        // Transitive: artifact signed by k2
        graph.AddEdge(new GraphEdge("artifact:transitive.dll", "key:sha256:k2", GraphEdgeType.SignedBy, "signed by"));
        // Identity
        graph.AddEdge(new GraphEdge("key:sha256:k1", "identity:github.com/org", GraphEdgeType.IdentityBoundTo, "identity bound to"));

        var result = ImpactAnalyzer.Analyze(graph, "key:sha256:k1");

        Assert.True(result.IsSuccess);
        var report = result.Value;
        Assert.Single(report.DirectArtifacts);
        Assert.Contains("artifact:direct.dll", report.DirectArtifacts);
        Assert.Single(report.TransitiveArtifacts);
        Assert.Contains("artifact:transitive.dll", report.TransitiveArtifacts);
        Assert.Single(report.EndorsedKeys);
        Assert.Single(report.BoundIdentities);
    }

    [Fact]
    public void Analyze_revoked_key_with_no_reason()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("key:sha256:k1", GraphNodeType.Key, "sha256:k1"));
        var revokedEdge = new GraphEdge("key:sha256:k1", "key:sha256:k1", GraphEdgeType.RevokedAt, "revoked");
        revokedEdge.Properties["revokedAt"] = "2026-02-01T00:00:00Z";
        // No reason property
        graph.AddEdge(revokedEdge);

        var result = ImpactAnalyzer.Analyze(graph, "key:sha256:k1");

        Assert.True(result.IsSuccess);
        var report = result.Value;
        Assert.True(report.IsRevoked);
        Assert.Equal("2026-02-01T00:00:00Z", report.RevokedAt);
        Assert.Null(report.RevocationReason);
    }

    [Fact]
    public void Analyze_deep_endorsement_chain_three_levels()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("artifact:deep.dll", GraphNodeType.Artifact, "deep.dll"));
        graph.AddNode(new GraphNode("key:sha256:root", GraphNodeType.Key, "root"));
        graph.AddNode(new GraphNode("key:sha256:mid", GraphNodeType.Key, "mid"));
        graph.AddNode(new GraphNode("key:sha256:leaf", GraphNodeType.Key, "leaf"));
        // leaf endorsed by mid, mid endorsed by root
        graph.AddEdge(new GraphEdge("key:sha256:leaf", "key:sha256:mid", GraphEdgeType.EndorsedBy, "endorsed by"));
        graph.AddEdge(new GraphEdge("key:sha256:mid", "key:sha256:root", GraphEdgeType.EndorsedBy, "endorsed by"));
        // Artifact signed by leaf
        graph.AddEdge(new GraphEdge("artifact:deep.dll", "key:sha256:leaf", GraphEdgeType.SignedBy, "signed by"));

        var result = ImpactAnalyzer.Analyze(graph, "key:sha256:root");

        Assert.True(result.IsSuccess);
        var report = result.Value;
        Assert.Empty(report.DirectArtifacts);
        Assert.Single(report.TransitiveArtifacts);
        Assert.Equal("artifact:deep.dll", report.TransitiveArtifacts[0]);
        // root directly endorses mid
        Assert.Single(report.EndorsedKeys);
        Assert.Equal("key:sha256:mid", report.EndorsedKeys[0]);
    }

    [Fact]
    public void Analyze_cycle_in_endorsement_chain_handled()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("artifact:cycled.dll", GraphNodeType.Artifact, "cycled.dll"));
        graph.AddNode(new GraphNode("key:sha256:k1", GraphNodeType.Key, "k1"));
        graph.AddNode(new GraphNode("key:sha256:k2", GraphNodeType.Key, "k2"));
        // k2 endorsed by k1, k1 endorsed by k2 (cycle)
        graph.AddEdge(new GraphEdge("key:sha256:k2", "key:sha256:k1", GraphEdgeType.EndorsedBy, "endorsed by"));
        graph.AddEdge(new GraphEdge("key:sha256:k1", "key:sha256:k2", GraphEdgeType.EndorsedBy, "endorsed by"));
        // Artifact signed by k2
        graph.AddEdge(new GraphEdge("artifact:cycled.dll", "key:sha256:k2", GraphEdgeType.SignedBy, "signed by"));

        var result = ImpactAnalyzer.Analyze(graph, "key:sha256:k1");

        Assert.True(result.IsSuccess);
        var report = result.Value;
        // Should find cycled.dll as transitive despite cycle
        Assert.Single(report.TransitiveArtifacts);
        Assert.Equal("artifact:cycled.dll", report.TransitiveArtifacts[0]);
    }

    [Fact]
    public void Analyze_always_recommends_rotate_and_audit()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("key:sha256:k1", GraphNodeType.Key, "sha256:k1"));

        var result = ImpactAnalyzer.Analyze(graph, "key:sha256:k1");

        Assert.True(result.IsSuccess);
        var report = result.Value;
        Assert.Contains(report.Recommendations, r => r.Contains("Rotate to a new key pair"));
        Assert.Contains(report.Recommendations, r => r.Contains("Audit transparency logs"));
    }

    [Fact]
    public void Analyze_direct_artifacts_recommends_resign()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("artifact:a.dll", GraphNodeType.Artifact, "a.dll"));
        graph.AddNode(new GraphNode("key:sha256:k1", GraphNodeType.Key, "sha256:k1"));
        graph.AddEdge(new GraphEdge("artifact:a.dll", "key:sha256:k1", GraphEdgeType.SignedBy, "signed by"));

        var result = ImpactAnalyzer.Analyze(graph, "key:sha256:k1");

        Assert.True(result.IsSuccess);
        Assert.Contains(result.Value.Recommendations, r => r.Contains("Re-sign 1 directly signed artifact"));
    }

    [Fact]
    public void Analyze_transitive_artifacts_recommends_reevaluate()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("artifact:t.dll", GraphNodeType.Artifact, "t.dll"));
        graph.AddNode(new GraphNode("key:sha256:root", GraphNodeType.Key, "root"));
        graph.AddNode(new GraphNode("key:sha256:child", GraphNodeType.Key, "child"));
        graph.AddEdge(new GraphEdge("key:sha256:child", "key:sha256:root", GraphEdgeType.EndorsedBy, "endorsed by"));
        graph.AddEdge(new GraphEdge("artifact:t.dll", "key:sha256:child", GraphEdgeType.SignedBy, "signed by"));

        var result = ImpactAnalyzer.Analyze(graph, "key:sha256:root");

        Assert.True(result.IsSuccess);
        Assert.Contains(result.Value.Recommendations, r => r.Contains("Re-evaluate 1 transitively affected artifact"));
    }

    [Fact]
    public void Analyze_endorsed_keys_recommends_review()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("key:sha256:root", GraphNodeType.Key, "root"));
        graph.AddNode(new GraphNode("key:sha256:child", GraphNodeType.Key, "child"));
        graph.AddEdge(new GraphEdge("key:sha256:child", "key:sha256:root", GraphEdgeType.EndorsedBy, "endorsed by"));

        var result = ImpactAnalyzer.Analyze(graph, "key:sha256:root");

        Assert.True(result.IsSuccess);
        Assert.Contains(result.Value.Recommendations, r => r.Contains("Review endorsement of 1 downstream key"));
    }

    [Fact]
    public void Analyze_key_label_null_when_label_equals_fingerprint()
    {
        var graph = new TrustGraph();
        // Label matches fingerprint — KeyLabel should be null
        graph.AddNode(new GraphNode("key:sha256:k1", GraphNodeType.Key, "sha256:k1"));

        var result = ImpactAnalyzer.Analyze(graph, "key:sha256:k1");

        Assert.True(result.IsSuccess);
        Assert.Null(result.Value.KeyLabel);
    }

    [Fact]
    public void Analyze_key_label_set_when_label_differs_from_fingerprint()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("key:sha256:k1", GraphNodeType.Key, "my-display-name"));

        var result = ImpactAnalyzer.Analyze(graph, "key:sha256:k1");

        Assert.True(result.IsSuccess);
        Assert.Equal("my-display-name", result.Value.KeyLabel);
    }

    [Fact]
    public void Analyze_deduplicates_transitive_artifacts()
    {
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("artifact:shared.dll", GraphNodeType.Artifact, "shared.dll"));
        graph.AddNode(new GraphNode("key:sha256:root", GraphNodeType.Key, "root"));
        graph.AddNode(new GraphNode("key:sha256:child1", GraphNodeType.Key, "child1"));
        graph.AddNode(new GraphNode("key:sha256:child2", GraphNodeType.Key, "child2"));
        graph.AddEdge(new GraphEdge("key:sha256:child1", "key:sha256:root", GraphEdgeType.EndorsedBy, "endorsed by"));
        graph.AddEdge(new GraphEdge("key:sha256:child2", "key:sha256:root", GraphEdgeType.EndorsedBy, "endorsed by"));
        // Same artifact signed by both children
        graph.AddEdge(new GraphEdge("artifact:shared.dll", "key:sha256:child1", GraphEdgeType.SignedBy, "signed by"));
        graph.AddEdge(new GraphEdge("artifact:shared.dll", "key:sha256:child2", GraphEdgeType.SignedBy, "signed by"));

        var result = ImpactAnalyzer.Analyze(graph, "key:sha256:root");

        Assert.True(result.IsSuccess);
        Assert.Single(result.Value.TransitiveArtifacts);
        Assert.Equal("artifact:shared.dll", result.Value.TransitiveArtifacts[0]);
    }

    [Fact]
    public void Analyze_revoked_edge_to_separate_node()
    {
        // The RevokedImpact tests use a different pattern: edge to separate revoke node
        var graph = new TrustGraph();
        graph.AddNode(new GraphNode("key:sha256:k1", GraphNodeType.Key, "sha256:k1"));
        graph.AddNode(new GraphNode("revoke:key:sha256:k1", GraphNodeType.LogRecord, "Revocation"));
        graph.AddEdge(new GraphEdge("key:sha256:k1", "revoke:key:sha256:k1", GraphEdgeType.RevokedAt, "revoked"));

        var result = ImpactAnalyzer.Analyze(graph, "key:sha256:k1");

        Assert.True(result.IsSuccess);
        Assert.True(result.Value.IsRevoked);
    }
}
