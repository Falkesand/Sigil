namespace Sigil.Core.Tests.Attestation;

/// <summary>
/// Shared xUnit collection to serialize tests that modify environment variables.
/// Prevents race conditions when test classes run in parallel.
/// </summary>
[CollectionDefinition("Environment")]
public sealed class EnvironmentCollectionFixture;
