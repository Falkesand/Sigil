using Sigil.Attestation;
using Sigil.Graph;

namespace Sigil.Core.Tests.Graph;

public class GraphBuilderAttestationTests
{
    private static DsseEnvelope CreateDsseEnvelope(
        string keyId = "sha256:attkey",
        string algorithm = "ecdsa-p256")
    {
        return new DsseEnvelope
        {
            Payload = "ignored-for-graph-builder",
            Signatures =
            [
                new DsseSignature
                {
                    KeyId = keyId,
                    Algorithm = algorithm,
                    PublicKey = "AAAAAAAAAAAAAAAAAAA",
                    Sig = "CCCC",
                    Timestamp = "2026-01-01T00:00:00Z"
                }
            ]
        };
    }

    private static InTotoStatement CreateStatement(
        string subjectName = "test.dll",
        string predicateType = "https://slsa.dev/provenance/v1")
    {
        return new InTotoStatement
        {
            Subject =
            [
                new InTotoSubject
                {
                    Name = subjectName,
                    Digest = new Dictionary<string, string> { ["sha256"] = "abc123" }
                }
            ],
            PredicateType = predicateType
        };
    }

    [Fact]
    public void IngestAttestationEnvelope_creates_artifact_node_from_subject()
    {
        var graph = new TrustGraph();
        var envelope = CreateDsseEnvelope();
        var statement = CreateStatement(subjectName: "build-output.zip");

        GraphBuilder.IngestAttestationEnvelope(graph, envelope, statement);

        var node = graph.GetNode("artifact:build-output.zip");
        Assert.Equal(GraphNodeType.Artifact, node.Type);
        Assert.Equal("build-output.zip", node.Label);
    }

    [Fact]
    public void IngestAttestationEnvelope_creates_attestation_node()
    {
        var graph = new TrustGraph();
        var envelope = CreateDsseEnvelope();
        var statement = CreateStatement(
            subjectName: "app.exe",
            predicateType: "https://slsa.dev/provenance/v1");

        GraphBuilder.IngestAttestationEnvelope(graph, envelope, statement);

        var node = graph.GetNode("attestation:https://slsa.dev/provenance/v1:app.exe");
        Assert.Equal(GraphNodeType.Attestation, node.Type);
        Assert.Equal("https://slsa.dev/provenance/v1 for app.exe", node.Label);
    }

    [Fact]
    public void IngestAttestationEnvelope_creates_attested_by_edge()
    {
        var graph = new TrustGraph();
        var envelope = CreateDsseEnvelope();
        var statement = CreateStatement(subjectName: "target.dll");

        GraphBuilder.IngestAttestationEnvelope(graph, envelope, statement);

        var edges = graph.GetOutgoingEdges("artifact:target.dll");
        Assert.Single(edges);
        Assert.Equal(GraphEdgeType.AttestedBy, edges[0].Type);
        Assert.Equal("attestation:https://slsa.dev/provenance/v1:target.dll", edges[0].TargetId);
    }

    [Fact]
    public void IngestAttestationEnvelope_creates_key_node_from_dsse_signature()
    {
        var graph = new TrustGraph();
        var envelope = CreateDsseEnvelope(keyId: "sha256:dssekey", algorithm: "ecdsa-p384");
        var statement = CreateStatement();

        GraphBuilder.IngestAttestationEnvelope(graph, envelope, statement);

        var node = graph.GetNode("key:sha256:dssekey");
        Assert.Equal(GraphNodeType.Key, node.Type);
        Assert.Equal("ecdsa-p384", node.Properties["algorithm"]);
    }

    [Fact]
    public void IngestAttestationEnvelope_creates_signed_by_edge_from_attestation_to_key()
    {
        var graph = new TrustGraph();
        var envelope = CreateDsseEnvelope(keyId: "sha256:sigkey");
        var statement = CreateStatement(subjectName: "signed.dll");

        GraphBuilder.IngestAttestationEnvelope(graph, envelope, statement);

        var attestationId = "attestation:https://slsa.dev/provenance/v1:signed.dll";
        var edges = graph.GetOutgoingEdges(attestationId);
        Assert.Single(edges);
        Assert.Equal(GraphEdgeType.SignedBy, edges[0].Type);
        Assert.Equal("key:sha256:sigkey", edges[0].TargetId);
    }

    [Fact]
    public void IngestAttestationEnvelope_handles_multiple_subjects()
    {
        var graph = new TrustGraph();
        var envelope = CreateDsseEnvelope();
        var statement = new InTotoStatement
        {
            Subject =
            [
                new InTotoSubject
                {
                    Name = "alpha.dll",
                    Digest = new Dictionary<string, string> { ["sha256"] = "aaa" }
                },
                new InTotoSubject
                {
                    Name = "beta.dll",
                    Digest = new Dictionary<string, string> { ["sha256"] = "bbb" }
                }
            ],
            PredicateType = "https://slsa.dev/provenance/v1"
        };

        GraphBuilder.IngestAttestationEnvelope(graph, envelope, statement);

        Assert.NotNull(graph.TryGetNode("artifact:alpha.dll"));
        Assert.NotNull(graph.TryGetNode("artifact:beta.dll"));
        Assert.NotNull(graph.TryGetNode("attestation:https://slsa.dev/provenance/v1:alpha.dll"));
        Assert.NotNull(graph.TryGetNode("attestation:https://slsa.dev/provenance/v1:beta.dll"));
    }

    [Fact]
    public void IngestAttestationEnvelope_multiple_signatures_create_multiple_keys()
    {
        var graph = new TrustGraph();
        var envelope = new DsseEnvelope
        {
            Payload = "ignored",
            Signatures =
            [
                new DsseSignature
                {
                    KeyId = "sha256:sig1",
                    Algorithm = "ecdsa-p256",
                    PublicKey = "AAAAAAAAAAAAAAAAAAA",
                    Sig = "s1",
                    Timestamp = "2026-01-01T00:00:00Z"
                },
                new DsseSignature
                {
                    KeyId = "sha256:sig2",
                    Algorithm = "ecdsa-p384",
                    PublicKey = "BBBBBBBBBBBBBBBBBBB",
                    Sig = "s2",
                    Timestamp = "2026-01-01T00:00:00Z"
                }
            ]
        };
        var statement = CreateStatement(subjectName: "dual.dll");

        GraphBuilder.IngestAttestationEnvelope(graph, envelope, statement);

        Assert.NotNull(graph.TryGetNode("key:sha256:sig1"));
        Assert.NotNull(graph.TryGetNode("key:sha256:sig2"));
        var attestationEdges = graph.GetOutgoingEdges("attestation:https://slsa.dev/provenance/v1:dual.dll");
        var signedByEdges = attestationEdges.Where(e => e.Type == GraphEdgeType.SignedBy).ToList();
        Assert.Equal(2, signedByEdges.Count);
    }
}
