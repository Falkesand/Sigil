using Sigil.Crypto;

namespace Sigil.Core.Tests.Crypto;

[Collection("CryptoProviderRegistry")]
public class CryptoProviderRegistryTests : IDisposable
{
    public CryptoProviderRegistryTests()
    {
        CryptoProviderRegistry.Reset();
    }

    public void Dispose()
    {
        CryptoProviderRegistry.Reset();
    }

    private static CryptoProviderRegistration CreateDummyRegistration(
        Func<ISigner>? generate = null,
        Func<byte[], ISigner>? fromPkcs8 = null,
        Func<ReadOnlyMemory<char>, ReadOnlyMemory<char>, ISigner>? fromPem = null,
        Func<byte[], IVerifier>? fromSpki = null)
    {
        return new CryptoProviderRegistration
        {
            Generate = generate ?? (() => throw new NotImplementedException()),
            FromPkcs8 = fromPkcs8 ?? (_ => throw new NotImplementedException()),
            FromPem = fromPem ?? ((_, _) => throw new NotImplementedException()),
            FromSpki = fromSpki ?? (_ => throw new NotImplementedException()),
        };
    }

    [Fact]
    public void Register_And_TryGet_Returns_Registration()
    {
        var registration = CreateDummyRegistration();
        CryptoProviderRegistry.Register(SigningAlgorithm.Ed25519, registration);

        var found = CryptoProviderRegistry.TryGet(SigningAlgorithm.Ed25519, out var result);

        Assert.True(found);
        Assert.Same(registration, result);
    }

    [Fact]
    public void TryGet_Unregistered_Algorithm_Returns_False()
    {
        var found = CryptoProviderRegistry.TryGet(SigningAlgorithm.Ed25519, out var result);

        Assert.False(found);
        Assert.Null(result);
    }

    [Fact]
    public void Register_Same_Algorithm_Twice_Throws_InvalidOperationException()
    {
        var registration = CreateDummyRegistration();
        CryptoProviderRegistry.Register(SigningAlgorithm.Ed25519, registration);

        Assert.Throws<InvalidOperationException>(
            () => CryptoProviderRegistry.Register(SigningAlgorithm.Ed25519, registration));
    }

    [Fact]
    public void Register_Null_Registration_Throws_ArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(
            () => CryptoProviderRegistry.Register(SigningAlgorithm.Ed25519, null!));
    }

    [Fact]
    public void Reset_Clears_All_Registrations()
    {
        CryptoProviderRegistry.Register(SigningAlgorithm.Ed25519, CreateDummyRegistration());

        CryptoProviderRegistry.Reset();

        Assert.False(CryptoProviderRegistry.TryGet(SigningAlgorithm.Ed25519, out _));
    }

    [Fact]
    public void Generate_Via_Factory_Delegates_To_Registered_Provider()
    {
        var callCount = 0;
        var registration = CreateDummyRegistration(
            generate: () => { callCount++; return ECDsaP256Signer.Generate(); });
        CryptoProviderRegistry.Register(SigningAlgorithm.Ed25519, registration);

        using var signer = SignerFactory.Generate(SigningAlgorithm.Ed25519);

        Assert.Equal(1, callCount);
        Assert.NotNull(signer);
    }

    [Fact]
    public void FromPkcs8_Via_Registry_Delegates_To_Registered_Provider()
    {
        var callCount = 0;
        var registration = CreateDummyRegistration(
            fromPkcs8: bytes => { callCount++; return ECDsaP256Signer.Generate(); });
        CryptoProviderRegistry.Register(SigningAlgorithm.Ed25519, registration);

        // Verify the TryGet path exists and the delegate works
        Assert.True(CryptoProviderRegistry.TryGet(SigningAlgorithm.Ed25519, out var provider));
        using var signer = provider!.FromPkcs8(new byte[] { 1, 2, 3 });
        Assert.Equal(1, callCount);
    }

    [Fact]
    public void FromSpki_Via_VerifierFactory_Delegates_To_Registered_Provider()
    {
        var callCount = 0;
        var registration = CreateDummyRegistration(
            fromSpki: bytes =>
            {
                callCount++;
                return ECDsaP256Verifier.FromPublicKey(ECDsaP256Signer.Generate().PublicKey);
            });
        CryptoProviderRegistry.Register(SigningAlgorithm.Ed25519, registration);

        using var verifier = VerifierFactory.CreateFromPublicKey(new byte[] { 1 }, "ed25519");

        Assert.Equal(1, callCount);
    }

    [Fact]
    public void Existing_Algorithms_Still_Work_After_Registry_Populated()
    {
        CryptoProviderRegistry.Register(SigningAlgorithm.Ed25519, CreateDummyRegistration());

        using var signer = SignerFactory.Generate(SigningAlgorithm.ECDsaP256);
        Assert.Equal(SigningAlgorithm.ECDsaP256, signer.Algorithm);
    }

    [Fact]
    public void Existing_Ed25519_NotSupportedException_When_No_Provider_Registered()
    {
        // With no provider registered, Ed25519 should still throw NotSupportedException
        Assert.Throws<NotSupportedException>(() => SignerFactory.Generate(SigningAlgorithm.Ed25519));
    }

    [Fact]
    public void Multiple_Algorithms_Can_Be_Registered()
    {
        var reg1 = CreateDummyRegistration();
        var reg2 = CreateDummyRegistration();

        CryptoProviderRegistry.Register(SigningAlgorithm.Ed25519, reg1);
        // Use a different algorithm value — in real usage this would be Ed448 etc.
        // For now, register for an existing algorithm just to test multiple registrations.
        // We'll use ECDsaP256 — the factory will prefer the registry over the built-in.
        CryptoProviderRegistry.Register(SigningAlgorithm.ECDsaP256, reg2);

        Assert.True(CryptoProviderRegistry.TryGet(SigningAlgorithm.Ed25519, out var r1));
        Assert.Same(reg1, r1);
        Assert.True(CryptoProviderRegistry.TryGet(SigningAlgorithm.ECDsaP256, out var r2));
        Assert.Same(reg2, r2);
    }
}
