using Sigil.Graph;
using Sigil.Signing;

namespace Sigil.Core.Tests.Graph;

public class GraphBuilderManifestTests
{
    private static ManifestEnvelope CreateManifest(
        List<SubjectDescriptor>? subjects = null,
        string keyId = "sha256:mkey",
        string algorithm = "ecdsa-p256")
    {
        return new ManifestEnvelope
        {
            Kind = "manifest",
            Subjects = subjects ??
            [
                new SubjectDescriptor
                {
                    Name = "file1.txt",
                    Digests = new Dictionary<string, string> { ["sha256"] = "aaa" }
                }
            ],
            Signatures =
            [
                new SignatureEntry
                {
                    KeyId = keyId,
                    Algorithm = algorithm,
                    PublicKey = "AAAAAAAAAAAAAAAAAAA",
                    Value = "BBBB",
                    Timestamp = "2026-01-01T00:00:00Z"
                }
            ]
        };
    }

    [Fact]
    public void IngestManifestEnvelope_creates_root_artifact_node()
    {
        var graph = new TrustGraph();
        var envelope = CreateManifest();

        GraphBuilder.IngestManifestEnvelope(graph, envelope, "release.manifest.sig.json");

        var node = graph.GetNode("artifact:release.manifest.sig.json");
        Assert.Equal(GraphNodeType.Artifact, node.Type);
        Assert.Equal("release.manifest.sig.json", node.Label);
    }

    [Fact]
    public void IngestManifestEnvelope_sets_kind_property_on_root()
    {
        var graph = new TrustGraph();
        var envelope = CreateManifest();

        GraphBuilder.IngestManifestEnvelope(graph, envelope, "release.manifest.sig.json");

        var node = graph.GetNode("artifact:release.manifest.sig.json");
        Assert.Equal("manifest", node.Properties["kind"]);
    }

    [Fact]
    public void IngestManifestEnvelope_creates_subject_artifact_nodes()
    {
        var graph = new TrustGraph();
        var envelope = CreateManifest(subjects:
        [
            new SubjectDescriptor
            {
                Name = "app.exe",
                Digests = new Dictionary<string, string> { ["sha256"] = "bbb" }
            }
        ]);

        GraphBuilder.IngestManifestEnvelope(graph, envelope, "build.manifest.sig.json");

        var node = graph.GetNode("artifact:app.exe");
        Assert.Equal(GraphNodeType.Artifact, node.Type);
        Assert.Equal("app.exe", node.Label);
    }

    [Fact]
    public void IngestManifestEnvelope_creates_contained_in_edges()
    {
        var graph = new TrustGraph();
        var envelope = CreateManifest(subjects:
        [
            new SubjectDescriptor
            {
                Name = "lib.dll",
                Digests = new Dictionary<string, string> { ["sha256"] = "ccc" }
            }
        ]);

        GraphBuilder.IngestManifestEnvelope(graph, envelope, "dist.manifest.sig.json");

        var edges = graph.GetOutgoingEdges("artifact:lib.dll");
        Assert.Single(edges);
        Assert.Equal(GraphEdgeType.ContainedIn, edges[0].Type);
        Assert.Equal("artifact:dist.manifest.sig.json", edges[0].TargetId);
    }

    [Fact]
    public void IngestManifestEnvelope_creates_key_node_from_signature()
    {
        var graph = new TrustGraph();
        var envelope = CreateManifest(keyId: "sha256:manifest-key", algorithm: "rsa-pss-sha256");

        GraphBuilder.IngestManifestEnvelope(graph, envelope, "m.manifest.sig.json");

        var node = graph.GetNode("key:sha256:manifest-key");
        Assert.Equal(GraphNodeType.Key, node.Type);
        Assert.Equal("rsa-pss-sha256", node.Properties["algorithm"]);
    }

    [Fact]
    public void IngestManifestEnvelope_creates_signed_by_edge_from_root_to_key()
    {
        var graph = new TrustGraph();
        var envelope = CreateManifest(keyId: "sha256:mk1");

        GraphBuilder.IngestManifestEnvelope(graph, envelope, "root.manifest.sig.json");

        var edges = graph.GetOutgoingEdges("artifact:root.manifest.sig.json");
        var signedBy = edges.First(e => e.Type == GraphEdgeType.SignedBy);
        Assert.Equal("key:sha256:mk1", signedBy.TargetId);
    }

    [Fact]
    public void IngestManifestEnvelope_handles_multiple_subjects()
    {
        var graph = new TrustGraph();
        var envelope = CreateManifest(subjects:
        [
            new SubjectDescriptor
            {
                Name = "a.dll",
                Digests = new Dictionary<string, string> { ["sha256"] = "111" }
            },
            new SubjectDescriptor
            {
                Name = "b.dll",
                Digests = new Dictionary<string, string> { ["sha256"] = "222" }
            },
            new SubjectDescriptor
            {
                Name = "c.dll",
                Digests = new Dictionary<string, string> { ["sha256"] = "333" }
            }
        ]);

        GraphBuilder.IngestManifestEnvelope(graph, envelope, "multi.manifest.sig.json");

        Assert.NotNull(graph.TryGetNode("artifact:a.dll"));
        Assert.NotNull(graph.TryGetNode("artifact:b.dll"));
        Assert.NotNull(graph.TryGetNode("artifact:c.dll"));
        var rootIncoming = graph.GetIncomingEdges("artifact:multi.manifest.sig.json");
        Assert.Equal(3, rootIncoming.Count);
    }

    [Fact]
    public void IngestManifestEnvelope_deduplicates_subjects_across_manifests()
    {
        var graph = new TrustGraph();
        var subjects = new List<SubjectDescriptor>
        {
            new SubjectDescriptor
            {
                Name = "shared.dll",
                Digests = new Dictionary<string, string> { ["sha256"] = "same" }
            }
        };
        var envelope1 = CreateManifest(subjects: subjects, keyId: "sha256:k1");
        var envelope2 = CreateManifest(subjects: subjects, keyId: "sha256:k2");

        GraphBuilder.IngestManifestEnvelope(graph, envelope1, "m1.manifest.sig.json");
        GraphBuilder.IngestManifestEnvelope(graph, envelope2, "m2.manifest.sig.json");

        var sharedNodes = graph.AllNodes.Where(n => n.Id == "artifact:shared.dll").ToList();
        Assert.Single(sharedNodes);
    }
}
