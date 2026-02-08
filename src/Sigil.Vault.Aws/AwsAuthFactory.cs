using Amazon;
using Amazon.KeyManagementService;

namespace Sigil.Vault.Aws;

internal static class AwsAuthFactory
{
    public static VaultResult<AmazonKeyManagementServiceClient> CreateClient()
    {
        try
        {
            var region = Environment.GetEnvironmentVariable("AWS_REGION");
            if (string.IsNullOrWhiteSpace(region))
            {
                return VaultResult<AmazonKeyManagementServiceClient>.Fail(
                    VaultErrorKind.ConfigurationError,
                    "AWS_REGION environment variable not set");
            }

            var regionEndpoint = RegionEndpoint.GetBySystemName(region);
            var client = new AmazonKeyManagementServiceClient(regionEndpoint);

            return VaultResult<AmazonKeyManagementServiceClient>.Ok(client);
        }
        catch (Exception ex)
        {
            return VaultResult<AmazonKeyManagementServiceClient>.Fail(
                VaultErrorKind.AuthenticationFailed,
                $"Failed to create AWS KMS client: {ex.Message}");
        }
    }
}
