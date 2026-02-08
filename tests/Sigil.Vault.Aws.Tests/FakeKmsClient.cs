using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using Amazon.Runtime;
using Amazon.Runtime.Endpoints;

namespace Sigil.Vault.Aws.Tests;

/// <summary>
/// Minimal stub implementing IAmazonKeyManagementService for unit tests.
/// All methods throw NotImplementedException unless overridden via constructor delegates.
/// </summary>
#pragma warning disable CA1506 // Avoid excessive class coupling — stub must implement all interface members
internal sealed class FakeKmsClient : IAmazonKeyManagementService
{
    private readonly Func<SignRequest, CancellationToken, Task<SignResponse>>? _signHandler;
    private readonly Func<GetPublicKeyRequest, CancellationToken, Task<GetPublicKeyResponse>>? _getPublicKeyHandler;

    public FakeKmsClient(
        Func<SignRequest, CancellationToken, Task<SignResponse>>? signHandler = null,
        Func<GetPublicKeyRequest, CancellationToken, Task<GetPublicKeyResponse>>? getPublicKeyHandler = null)
    {
        _signHandler = signHandler;
        _getPublicKeyHandler = getPublicKeyHandler;
    }

    public IKeyManagementServicePaginatorFactory Paginators =>
        throw new NotImplementedException();

    public IClientConfig Config => throw new NotImplementedException();

    // Request-object overloads
    public Task<CancelKeyDeletionResponse> CancelKeyDeletionAsync(CancelKeyDeletionRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<ConnectCustomKeyStoreResponse> ConnectCustomKeyStoreAsync(ConnectCustomKeyStoreRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<CreateAliasResponse> CreateAliasAsync(CreateAliasRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<CreateCustomKeyStoreResponse> CreateCustomKeyStoreAsync(CreateCustomKeyStoreRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<CreateGrantResponse> CreateGrantAsync(CreateGrantRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<CreateKeyResponse> CreateKeyAsync(CreateKeyRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<DecryptResponse> DecryptAsync(DecryptRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<DeleteAliasResponse> DeleteAliasAsync(DeleteAliasRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<DeleteCustomKeyStoreResponse> DeleteCustomKeyStoreAsync(DeleteCustomKeyStoreRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<DeleteImportedKeyMaterialResponse> DeleteImportedKeyMaterialAsync(DeleteImportedKeyMaterialRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<DeriveSharedSecretResponse> DeriveSharedSecretAsync(DeriveSharedSecretRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<DescribeCustomKeyStoresResponse> DescribeCustomKeyStoresAsync(DescribeCustomKeyStoresRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<DescribeKeyResponse> DescribeKeyAsync(DescribeKeyRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<DisableKeyResponse> DisableKeyAsync(DisableKeyRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<DisableKeyRotationResponse> DisableKeyRotationAsync(DisableKeyRotationRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<DisconnectCustomKeyStoreResponse> DisconnectCustomKeyStoreAsync(DisconnectCustomKeyStoreRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<EnableKeyResponse> EnableKeyAsync(EnableKeyRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<EnableKeyRotationResponse> EnableKeyRotationAsync(EnableKeyRotationRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<EncryptResponse> EncryptAsync(EncryptRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<GenerateDataKeyResponse> GenerateDataKeyAsync(GenerateDataKeyRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<GenerateDataKeyPairResponse> GenerateDataKeyPairAsync(GenerateDataKeyPairRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<GenerateDataKeyPairWithoutPlaintextResponse> GenerateDataKeyPairWithoutPlaintextAsync(GenerateDataKeyPairWithoutPlaintextRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<GenerateDataKeyWithoutPlaintextResponse> GenerateDataKeyWithoutPlaintextAsync(GenerateDataKeyWithoutPlaintextRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<GenerateMacResponse> GenerateMacAsync(GenerateMacRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<GenerateRandomResponse> GenerateRandomAsync(GenerateRandomRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<GetKeyPolicyResponse> GetKeyPolicyAsync(GetKeyPolicyRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<GetKeyRotationStatusResponse> GetKeyRotationStatusAsync(GetKeyRotationStatusRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<GetParametersForImportResponse> GetParametersForImportAsync(GetParametersForImportRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<GetPublicKeyResponse> GetPublicKeyAsync(GetPublicKeyRequest request, CancellationToken cancellationToken = default)
    {
        if (_getPublicKeyHandler is not null)
            return _getPublicKeyHandler(request, cancellationToken);
        throw new NotImplementedException();
    }

    public Task<ImportKeyMaterialResponse> ImportKeyMaterialAsync(ImportKeyMaterialRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<ListAliasesResponse> ListAliasesAsync(ListAliasesRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<ListGrantsResponse> ListGrantsAsync(ListGrantsRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<ListKeyPoliciesResponse> ListKeyPoliciesAsync(ListKeyPoliciesRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<ListKeyRotationsResponse> ListKeyRotationsAsync(ListKeyRotationsRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<ListKeysResponse> ListKeysAsync(ListKeysRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<ListResourceTagsResponse> ListResourceTagsAsync(ListResourceTagsRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<ListRetirableGrantsResponse> ListRetirableGrantsAsync(ListRetirableGrantsRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<PutKeyPolicyResponse> PutKeyPolicyAsync(PutKeyPolicyRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<ReEncryptResponse> ReEncryptAsync(ReEncryptRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<ReplicateKeyResponse> ReplicateKeyAsync(ReplicateKeyRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<RetireGrantResponse> RetireGrantAsync(RetireGrantRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<RevokeGrantResponse> RevokeGrantAsync(RevokeGrantRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<RotateKeyOnDemandResponse> RotateKeyOnDemandAsync(RotateKeyOnDemandRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<ScheduleKeyDeletionResponse> ScheduleKeyDeletionAsync(ScheduleKeyDeletionRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<SignResponse> SignAsync(SignRequest request, CancellationToken cancellationToken = default)
    {
        if (_signHandler is not null)
            return _signHandler(request, cancellationToken);
        throw new NotImplementedException();
    }

    public Task<TagResourceResponse> TagResourceAsync(TagResourceRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<UntagResourceResponse> UntagResourceAsync(UntagResourceRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<UpdateAliasResponse> UpdateAliasAsync(UpdateAliasRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<UpdateCustomKeyStoreResponse> UpdateCustomKeyStoreAsync(UpdateCustomKeyStoreRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<UpdateKeyDescriptionResponse> UpdateKeyDescriptionAsync(UpdateKeyDescriptionRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<UpdatePrimaryRegionResponse> UpdatePrimaryRegionAsync(UpdatePrimaryRegionRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<VerifyResponse> VerifyAsync(VerifyRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<VerifyMacResponse> VerifyMacAsync(VerifyMacRequest request, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    // Convenience overloads (simplified parameter signatures)
    public Task<CancelKeyDeletionResponse> CancelKeyDeletionAsync(string keyId, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<CreateAliasResponse> CreateAliasAsync(string aliasName, string targetKeyId, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<DeleteAliasResponse> DeleteAliasAsync(string aliasName, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<DescribeKeyResponse> DescribeKeyAsync(string keyId, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<DisableKeyResponse> DisableKeyAsync(string keyId, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<DisableKeyRotationResponse> DisableKeyRotationAsync(string keyId, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<EnableKeyResponse> EnableKeyAsync(string keyId, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<EnableKeyRotationResponse> EnableKeyRotationAsync(string keyId, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<GenerateRandomResponse> GenerateRandomAsync(int? numberOfBytes, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<GetKeyPolicyResponse> GetKeyPolicyAsync(string keyId, string policyName, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<GetKeyRotationStatusResponse> GetKeyRotationStatusAsync(string keyId, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<ListRetirableGrantsResponse> ListRetirableGrantsAsync(string retiringPrincipal, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<ListRetirableGrantsResponse> ListRetirableGrantsAsync(CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<PutKeyPolicyResponse> PutKeyPolicyAsync(string keyId, string policyName, string policy, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<RetireGrantResponse> RetireGrantAsync(string grantToken, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<RevokeGrantResponse> RevokeGrantAsync(string keyId, string grantId, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<ScheduleKeyDeletionResponse> ScheduleKeyDeletionAsync(string keyId, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<ScheduleKeyDeletionResponse> ScheduleKeyDeletionAsync(string keyId, int? pendingWindowInDays, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<UpdateAliasResponse> UpdateAliasAsync(string aliasName, string targetKeyId, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    public Task<UpdateKeyDescriptionResponse> UpdateKeyDescriptionAsync(string keyId, string description, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

    // IAmazonService / IDisposable
    public Endpoint DetermineServiceOperationEndpoint(AmazonWebServiceRequest request) =>
        throw new NotImplementedException();

    public void Dispose()
    {
        // No-op for test stub
    }
}
#pragma warning restore CA1506
