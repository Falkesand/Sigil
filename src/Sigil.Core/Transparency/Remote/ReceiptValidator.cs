using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Org.Webpki.JsonCanonicalizer;

namespace Sigil.Transparency.Remote;

public static class ReceiptValidator
{
    public static RemoteLogResult<bool> ValidateInclusionProof(
        RemoteInclusionProof proof, string leafHash)
    {
        ArgumentNullException.ThrowIfNull(proof);
        ArgumentNullException.ThrowIfNull(leafHash);

        byte[] leafHashBytes;
        try
        {
            leafHashBytes = Convert.FromHexString(leafHash);
        }
        catch (FormatException)
        {
            return RemoteLogResult<bool>.Fail(
                RemoteLogErrorKind.InvalidProof, "Leaf hash is not valid hex.");
        }

        var localProof = new InclusionProof
        {
            LeafIndex = proof.LeafIndex,
            TreeSize = proof.TreeSize,
            RootHash = proof.RootHash,
            Hashes = proof.Hashes
        };

        var verified = MerkleTree.VerifyInclusionProof(localProof, leafHashBytes);

        return verified
            ? RemoteLogResult<bool>.Ok(true)
            : RemoteLogResult<bool>.Fail(
                RemoteLogErrorKind.InvalidProof, "Inclusion proof verification failed.");
    }

    public static RemoteLogResult<bool> ValidateSignedCheckpoint(
        string signedCheckpointBase64, byte[] logPublicKey)
    {
        ArgumentNullException.ThrowIfNull(signedCheckpointBase64);
        ArgumentNullException.ThrowIfNull(logPublicKey);

        byte[] checkpointBytes;
        try
        {
            checkpointBytes = Convert.FromBase64String(signedCheckpointBase64);
        }
        catch (FormatException)
        {
            return RemoteLogResult<bool>.Fail(
                RemoteLogErrorKind.InvalidCheckpoint, "Signed checkpoint is not valid base64.");
        }

        // The checkpoint format is: JSON payload + "." + base64url signature
        var checkpointString = Encoding.UTF8.GetString(checkpointBytes);
        var dotIndex = checkpointString.LastIndexOf('.');
        if (dotIndex < 0)
        {
            return RemoteLogResult<bool>.Fail(
                RemoteLogErrorKind.InvalidCheckpoint, "Signed checkpoint has invalid format: missing separator.");
        }

        var payloadPart = checkpointString[..dotIndex];
        var signaturePart = checkpointString[(dotIndex + 1)..];

        byte[] signatureBytes;
        try
        {
            signatureBytes = Convert.FromBase64String(signaturePart);
        }
        catch (FormatException)
        {
            return RemoteLogResult<bool>.Fail(
                RemoteLogErrorKind.InvalidCheckpoint, "Checkpoint signature is not valid base64.");
        }

        // Canonicalize payload via JCS before verification
        byte[] payloadBytes;
        try
        {
            payloadBytes = new JsonCanonicalizer(payloadPart).GetEncodedUTF8();
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return RemoteLogResult<bool>.Fail(
                RemoteLogErrorKind.InvalidCheckpoint, $"Checkpoint payload is not valid JSON: {ex.Message}");
        }

        // Verify ECDSA signature with curve validation
        try
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(logPublicKey, out _);

            // Validate the key uses an acceptable curve (P-256, P-384, P-521)
            var keyParams = ecdsa.ExportParameters(false);
            var curveOid = keyParams.Curve.Oid?.Value;
            if (curveOid is not ("1.2.840.10045.3.1.7" or "1.3.132.0.34" or "1.3.132.0.35"))
            {
                return RemoteLogResult<bool>.Fail(
                    RemoteLogErrorKind.InvalidCheckpoint,
                    "Log public key uses an unsupported ECDSA curve. Expected P-256, P-384, or P-521.");
            }

            var verified = ecdsa.VerifyData(payloadBytes, signatureBytes, HashAlgorithmName.SHA256);

            return verified
                ? RemoteLogResult<bool>.Ok(true)
                : RemoteLogResult<bool>.Fail(
                    RemoteLogErrorKind.InvalidCheckpoint, "Checkpoint signature verification failed.");
        }
        catch (CryptographicException ex)
        {
            return RemoteLogResult<bool>.Fail(
                RemoteLogErrorKind.InvalidCheckpoint, $"Failed to verify checkpoint signature: {ex.Message}");
        }
    }

    public static RemoteLogResult<bool> ValidateReceipt(
        TransparencyReceipt receipt, string leafHash, byte[]? logPublicKey = null)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        ArgumentNullException.ThrowIfNull(leafHash);

        // Validate inclusion proof
        var proofResult = ValidateInclusionProof(receipt.InclusionProof, leafHash);
        if (!proofResult.IsSuccess)
            return proofResult;

        // If log public key provided, validate signed checkpoint
        if (logPublicKey is not null)
        {
            var checkpointResult = ValidateSignedCheckpoint(
                receipt.SignedCheckpoint, logPublicKey);
            if (!checkpointResult.IsSuccess)
                return checkpointResult;
        }

        return RemoteLogResult<bool>.Ok(true);
    }
}
