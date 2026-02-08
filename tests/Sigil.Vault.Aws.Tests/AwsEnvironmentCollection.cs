namespace Sigil.Vault.Aws.Tests;

/// <summary>
/// Shared xUnit collection to serialize tests that modify the AWS_REGION environment variable.
/// Prevents race conditions when test classes run in parallel.
/// </summary>
[CollectionDefinition("AwsEnvironment")]
public sealed class AwsEnvironmentFixture;
