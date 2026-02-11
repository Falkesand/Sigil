namespace Sigil.Cli.Commands;

/// <summary>
/// Abstraction for secure credential storage backed by OS-level facilities.
/// </summary>
public interface ICredentialStore
{
    /// <summary>
    /// Retrieves a stored secret by target name.
    /// Returns <see cref="CredentialStoreErrorKind.NotFound"/> if no credential exists.
    /// </summary>
    CredentialStoreResult<string> Retrieve(string targetName);

    /// <summary>
    /// Stores or overwrites a secret for the given target name.
    /// Returns <see cref="CredentialStoreErrorKind.InvalidTarget"/> for empty or oversized target names.
    /// </summary>
    CredentialStoreResult<bool> Store(string targetName, string secret);

    /// <summary>
    /// Deletes a stored credential by target name.
    /// Returns <see cref="CredentialStoreErrorKind.NotFound"/> if no credential exists.
    /// </summary>
    CredentialStoreResult<bool> Delete(string targetName);

    /// <summary>
    /// Lists all target names matching the given prefix.
    /// Returns an empty list if no credentials match.
    /// </summary>
    CredentialStoreResult<IReadOnlyList<string>> List(string prefix);
}
