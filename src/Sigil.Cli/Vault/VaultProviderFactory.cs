using Sigil.Vault;
using Sigil.Vault.Aws;
using Sigil.Vault.Azure;
using Sigil.Vault.Gcp;
using Sigil.Vault.HashiCorp;
using Sigil.Vault.Pkcs11;

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
            "pkcs11" => CreatePkcs11(),
            _ => VaultResult<IKeyProvider>.Fail(
                VaultErrorKind.ConfigurationError,
                $"Unknown vault provider: {vaultName}. Supported: hashicorp, azure, aws, gcp, pkcs11")
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

    private static VaultResult<IKeyProvider> CreatePkcs11()
    {
        var result = Pkcs11KeyProvider.CreateFromEnvironment();
        if (!result.IsSuccess)
            return VaultResult<IKeyProvider>.Fail(result.ErrorKind, result.ErrorMessage);
        return VaultResult<IKeyProvider>.Ok(result.Value);
    }
}
