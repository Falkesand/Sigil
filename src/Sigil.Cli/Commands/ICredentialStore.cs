namespace Sigil.Cli.Commands;

public interface ICredentialStore
{
    CredentialStoreResult<string> Retrieve(string targetName);
    CredentialStoreResult<bool> Store(string targetName, string secret);
    CredentialStoreResult<bool> Delete(string targetName);
    CredentialStoreResult<IReadOnlyList<string>> List(string prefix);
}
