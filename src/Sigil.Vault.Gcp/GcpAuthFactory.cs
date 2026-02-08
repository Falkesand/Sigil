using Google.Cloud.Kms.V1;

namespace Sigil.Vault.Gcp;

internal static class GcpAuthFactory
{
    public static async Task<VaultResult<KeyManagementServiceClient>> CreateClientAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var client = await KeyManagementServiceClient.CreateAsync(cancellationToken).ConfigureAwait(false);
            return VaultResult<KeyManagementServiceClient>.Ok(client);
        }
        catch (Exception ex)
        {
            return VaultResult<KeyManagementServiceClient>.Fail(
                VaultErrorKind.AuthenticationFailed,
                $"Failed to create GCP KMS client: {ex.Message}");
        }
    }

    public static VaultResult<KeyManagementServiceClient> CreateClient()
    {
        try
        {
            var client = KeyManagementServiceClient.Create();
            return VaultResult<KeyManagementServiceClient>.Ok(client);
        }
        catch (Exception ex)
        {
            return VaultResult<KeyManagementServiceClient>.Fail(
                VaultErrorKind.AuthenticationFailed,
                $"Failed to create GCP KMS client: {ex.Message}");
        }
    }
}
