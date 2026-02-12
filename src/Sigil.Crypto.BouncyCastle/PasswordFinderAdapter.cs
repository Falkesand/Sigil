using Org.BouncyCastle.OpenSsl;

namespace Sigil.Crypto.BouncyCastle;

/// <summary>
/// Adapter for BouncyCastle's <see cref="IPasswordFinder"/> interface.
/// Wraps a character array password for use with <see cref="PemReader"/>.
/// </summary>
internal sealed class PasswordFinderAdapter : IPasswordFinder
{
    private readonly char[] _password;

    public PasswordFinderAdapter(char[] password)
    {
        ArgumentNullException.ThrowIfNull(password);
        _password = password;
    }

    public char[] GetPassword() => (char[])_password.Clone();
}
