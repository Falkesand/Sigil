using Sigil.Vault;
using Sigil.Vault.Aws;
using Sigil.Vault.Azure;
using Sigil.Vault.Gcp;
using Sigil.Vault.HashiCorp;

namespace Sigil.Cli.Vault;

internal static class VaultProviderFactory
{
    public static VaultResult<IKeyProvider> Create(string vaultName)
    {
        return vaultName.ToLowerInvariant() switch
        {
            "hashicorp" => CreateHashiCorp(),
            "azure" => CreateAzure(),
            "aws" => CreateAws(),
            "gcp" => CreateGcp(),
            _ => VaultResult<IKeyProvider>.Fail(
                VaultErrorKind.ConfigurationError,
                $"Unknown vault provider: {vaultName}. Supported: hashicorp, azure, aws, gcp")
        };
    }

    private static VaultResult<IKeyProvider> CreateHashiCorp()
    {
        var provider = new HashiCorpKeyProvider();
        return VaultResult<IKeyProvider>.Ok(provider);
    }

    private static VaultResult<IKeyProvider> CreateAzure()
    {
        var result = AzureKeyVaultProvider.CreateFromEnvironment();
        if (!result.IsSuccess)
            return VaultResult<IKeyProvider>.Fail(result.ErrorKind, result.ErrorMessage);
        return VaultResult<IKeyProvider>.Ok(result.Value);
    }

    private static VaultResult<IKeyProvider> CreateAws()
    {
        var result = AwsKmsKeyProvider.Create();
        if (!result.IsSuccess)
            return VaultResult<IKeyProvider>.Fail(result.ErrorKind, result.ErrorMessage);
        return VaultResult<IKeyProvider>.Ok(result.Value);
    }

    private static VaultResult<IKeyProvider> CreateGcp()
    {
        var result = GcpKmsKeyProvider.Create();
        if (!result.IsSuccess)
            return VaultResult<IKeyProvider>.Fail(result.ErrorKind, result.ErrorMessage);
        return VaultResult<IKeyProvider>.Ok(result.Value);
    }
}
