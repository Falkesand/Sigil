using System.Text.Json;
using Secure.Sbom.Crypto;

namespace Secure.Sbom.Keys;

/// <summary>
/// File-based key store. Layout:
///   ~/.secure-sbom/keys/{fingerprint}/
///     public.pem
///     private.pem  (only if we own the key)
///     metadata.json
/// </summary>
public sealed class KeyStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    private readonly string _basePath;

    public KeyStore(string basePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(basePath);
        _basePath = basePath;
        Directory.CreateDirectory(_basePath);
    }

    public static KeyStore Default()
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return new KeyStore(Path.Combine(home, ".secure-sbom", "keys"));
    }

    /// <summary>
    /// Generates a new key pair, stores it, and returns the fingerprint.
    /// </summary>
    public KeyFingerprint GenerateKey(SigningAlgorithm algorithm = SigningAlgorithm.ECDsaP256, string? label = null, string? passphrase = null)
    {
        using var signer = algorithm switch
        {
            SigningAlgorithm.ECDsaP256 => ECDsaP256Signer.Generate(),
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm))
        };

        var spki = signer.PublicKey;
        var fingerprint = KeyFingerprint.Compute(spki);
        var keyDir = Path.Combine(_basePath, SanitizeDirectoryName(fingerprint.Value));

        Directory.CreateDirectory(keyDir);

        // Write public key PEM
        File.WriteAllText(Path.Combine(keyDir, "public.pem"), signer.ExportPublicKeyPem());

        // Write private key PEM (encrypted if passphrase provided)
        if (!string.IsNullOrEmpty(passphrase))
        {
            File.WriteAllText(Path.Combine(keyDir, "private.pem"), signer.ExportEncryptedPrivateKeyPem(passphrase));
        }
        else
        {
            File.WriteAllText(Path.Combine(keyDir, "private.pem"), signer.ExportPrivateKeyPem());
        }

        // Write metadata
        var metadata = new KeyMetadata
        {
            Algorithm = algorithm.ToCanonicalName(),
            Label = label,
            CreatedAt = DateTimeOffset.UtcNow,
            Fingerprint = fingerprint.Value,
            HasPrivateKey = true
        };

        File.WriteAllText(
            Path.Combine(keyDir, "metadata.json"),
            JsonSerializer.Serialize(metadata, JsonOptions));

        return fingerprint;
    }

    /// <summary>
    /// Lists all keys in the store.
    /// </summary>
    public IReadOnlyList<KeyMetadata> ListKeys()
    {
        var result = new List<KeyMetadata>();

        if (!Directory.Exists(_basePath))
            return result;

        foreach (var dir in Directory.GetDirectories(_basePath))
        {
            var metadataPath = Path.Combine(dir, "metadata.json");
            if (!File.Exists(metadataPath))
                continue;

            var json = File.ReadAllText(metadataPath);
            var metadata = JsonSerializer.Deserialize<KeyMetadata>(json);
            if (metadata is not null)
                result.Add(metadata);
        }

        return result;
    }

    /// <summary>
    /// Loads a signer (private key) for the given fingerprint.
    /// </summary>
    public ECDsaP256Signer LoadSigner(KeyFingerprint fingerprint, string? passphrase = null)
    {
        var keyDir = Path.Combine(_basePath, SanitizeDirectoryName(fingerprint.Value));
        var privatePemPath = Path.Combine(keyDir, "private.pem");

        if (!File.Exists(privatePemPath))
            throw new FileNotFoundException($"No private key found for {fingerprint.ShortId}.");

        var pem = File.ReadAllText(privatePemPath);

        if (pem.Contains("ENCRYPTED", StringComparison.Ordinal))
        {
            if (string.IsNullOrEmpty(passphrase))
                throw new InvalidOperationException("Private key is encrypted. Passphrase required.");

            var encrypted = DecodePem(pem);
            return ECDsaP256Signer.FromEncryptedPkcs8(encrypted, passphrase);
        }

        var pkcs8 = DecodePem(pem);
        return ECDsaP256Signer.FromPkcs8(pkcs8);
    }

    /// <summary>
    /// Loads a verifier (public key) for the given fingerprint.
    /// </summary>
    public ECDsaP256Verifier LoadVerifier(KeyFingerprint fingerprint)
    {
        var keyDir = Path.Combine(_basePath, SanitizeDirectoryName(fingerprint.Value));
        var publicPemPath = Path.Combine(keyDir, "public.pem");

        if (!File.Exists(publicPemPath))
            throw new FileNotFoundException($"No public key found for {fingerprint.ShortId}.");

        var pem = File.ReadAllText(publicPemPath);
        return ECDsaP256Verifier.FromPublicKeyPem(pem);
    }

    /// <summary>
    /// Returns the public key PEM for export.
    /// </summary>
    public string ExportPublicKeyPem(KeyFingerprint fingerprint)
    {
        var keyDir = Path.Combine(_basePath, SanitizeDirectoryName(fingerprint.Value));
        var publicPemPath = Path.Combine(keyDir, "public.pem");

        if (!File.Exists(publicPemPath))
            throw new FileNotFoundException($"No public key found for {fingerprint.ShortId}.");

        return File.ReadAllText(publicPemPath);
    }

    /// <summary>
    /// Imports a public key PEM into the store.
    /// </summary>
    public KeyFingerprint ImportPublicKey(string pem, string? label = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pem);

        // Parse the PEM to get the SPKI bytes for fingerprinting
        var verifier = ECDsaP256Verifier.FromPublicKeyPem(pem);
        var spki = verifier.PublicKey;
        var fingerprint = KeyFingerprint.Compute(spki);
        var keyDir = Path.Combine(_basePath, SanitizeDirectoryName(fingerprint.Value));

        if (Directory.Exists(keyDir))
            return fingerprint; // Already imported

        Directory.CreateDirectory(keyDir);

        File.WriteAllText(Path.Combine(keyDir, "public.pem"), pem);

        var metadata = new KeyMetadata
        {
            Algorithm = SigningAlgorithm.ECDsaP256.ToCanonicalName(),
            Label = label,
            CreatedAt = DateTimeOffset.UtcNow,
            Fingerprint = fingerprint.Value,
            HasPrivateKey = false
        };

        File.WriteAllText(
            Path.Combine(keyDir, "metadata.json"),
            JsonSerializer.Serialize(metadata, JsonOptions));

        return fingerprint;
    }

    public bool KeyExists(KeyFingerprint fingerprint)
    {
        var keyDir = Path.Combine(_basePath, SanitizeDirectoryName(fingerprint.Value));
        return Directory.Exists(keyDir) && File.Exists(Path.Combine(keyDir, "metadata.json"));
    }

    /// <summary>
    /// Decodes PEM content to raw bytes. Strips headers/footers and base64-decodes.
    /// </summary>
    private static byte[] DecodePem(string pem)
    {
        var lines = pem.Split('\n')
            .Select(l => l.Trim())
            .Where(l => !l.StartsWith("-----", StringComparison.Ordinal) && l.Length > 0);
        var base64 = string.Concat(lines);
        return Convert.FromBase64String(base64);
    }

    private static string SanitizeDirectoryName(string fingerprint)
    {
        // sha256:hex -> sha256_hex (filesystem-safe)
        return fingerprint.Replace(':', '_');
    }
}
