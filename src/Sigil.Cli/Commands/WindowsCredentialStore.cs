using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace Sigil.Cli.Commands;

[SupportedOSPlatform("windows")]
public sealed class WindowsCredentialStore : ICredentialStore
{
    private const int CredTypeGeneric = 1;
    // CRED_PERSIST_LOCAL_MACHINE (2): credential persists across logon sessions.
    // Still scoped to the current user profile via DPAPI, not machine-wide access.
    private const int CredPersistLocalMachine = 2;
    private const int ErrorNotFound = 1168;
    private const int MaxTargetLength = 337; // CRED_MAX_GENERIC_TARGET_NAME_LENGTH

    public CredentialStoreResult<string> Retrieve(string targetName)
    {
        ArgumentNullException.ThrowIfNull(targetName);

        if (string.IsNullOrWhiteSpace(targetName))
            return CredentialStoreResult<string>.Fail(
                CredentialStoreErrorKind.InvalidTarget, "Target name cannot be empty.");

        if (!NativeMethods.CredRead(targetName, CredTypeGeneric, 0, out var credPtr))
        {
            var error = Marshal.GetLastPInvokeError();
            if (error == ErrorNotFound)
                return CredentialStoreResult<string>.Fail(
                    CredentialStoreErrorKind.NotFound,
                    $"No credential found for target: {targetName}");

            return CredentialStoreResult<string>.Fail(
                CredentialStoreErrorKind.AccessDenied,
                $"Failed to read credential (error {error}).");
        }

        try
        {
            var cred = Marshal.PtrToStructure<NativeCredential>(credPtr);
            if (cred.CredentialBlobSize == 0 || cred.CredentialBlob == IntPtr.Zero)
                return CredentialStoreResult<string>.Fail(
                    CredentialStoreErrorKind.NotFound, "Credential has no data.");

            var blobBytes = new byte[cred.CredentialBlobSize];
            try
            {
                Marshal.Copy(cred.CredentialBlob, blobBytes, 0, (int)cred.CredentialBlobSize);
                return CredentialStoreResult<string>.Ok(Encoding.UTF8.GetString(blobBytes));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(blobBytes);
            }
        }
        finally
        {
            NativeMethods.CredFree(credPtr);
        }
    }

    public CredentialStoreResult<bool> Store(string targetName, string secret)
    {
        ArgumentNullException.ThrowIfNull(targetName);
        ArgumentNullException.ThrowIfNull(secret);

        if (string.IsNullOrWhiteSpace(targetName))
            return CredentialStoreResult<bool>.Fail(
                CredentialStoreErrorKind.InvalidTarget, "Target name cannot be empty.");

        if (targetName.Length > MaxTargetLength)
            return CredentialStoreResult<bool>.Fail(
                CredentialStoreErrorKind.InvalidTarget,
                $"Target name exceeds maximum length of {MaxTargetLength} characters.");

        var secretBytes = Encoding.UTF8.GetBytes(secret);
        try
        {
            var cred = new NativeCredential
            {
                Type = CredTypeGeneric,
                TargetName = targetName,
                CredentialBlobSize = (uint)secretBytes.Length,
                CredentialBlob = Marshal.AllocHGlobal(secretBytes.Length),
                Persist = CredPersistLocalMachine,
                UserName = Environment.UserName
            };

            try
            {
                Marshal.Copy(secretBytes, 0, cred.CredentialBlob, secretBytes.Length);

                if (!NativeMethods.CredWrite(ref cred, 0))
                {
                    var error = Marshal.GetLastPInvokeError();
                    return CredentialStoreResult<bool>.Fail(
                        CredentialStoreErrorKind.StoreFailed,
                        $"Failed to store credential (error {error}).");
                }

                return CredentialStoreResult<bool>.Ok(true);
            }
            finally
            {
                // Zero the unmanaged blob before freeing
                for (int i = 0; i < secretBytes.Length; i++)
                    Marshal.WriteByte(cred.CredentialBlob, i, 0);
                Marshal.FreeHGlobal(cred.CredentialBlob);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secretBytes);
        }
    }

    public CredentialStoreResult<bool> Delete(string targetName)
    {
        ArgumentNullException.ThrowIfNull(targetName);

        if (string.IsNullOrWhiteSpace(targetName))
            return CredentialStoreResult<bool>.Fail(
                CredentialStoreErrorKind.InvalidTarget, "Target name cannot be empty.");

        if (!NativeMethods.CredDelete(targetName, CredTypeGeneric, 0))
        {
            var error = Marshal.GetLastPInvokeError();
            if (error == ErrorNotFound)
                return CredentialStoreResult<bool>.Fail(
                    CredentialStoreErrorKind.NotFound,
                    $"No credential found for target: {targetName}");

            return CredentialStoreResult<bool>.Fail(
                CredentialStoreErrorKind.DeleteFailed,
                $"Failed to delete credential (error {error}).");
        }

        return CredentialStoreResult<bool>.Ok(true);
    }

    public CredentialStoreResult<IReadOnlyList<string>> List(string prefix)
    {
        ArgumentNullException.ThrowIfNull(prefix);

        var filter = prefix + "*";
        if (!NativeMethods.CredEnumerate(filter, 0, out var count, out var credArrayPtr))
        {
            var error = Marshal.GetLastPInvokeError();
            if (error == ErrorNotFound)
                return CredentialStoreResult<IReadOnlyList<string>>.Ok(Array.Empty<string>());

            return CredentialStoreResult<IReadOnlyList<string>>.Fail(
                CredentialStoreErrorKind.AccessDenied,
                $"Failed to enumerate credentials (error {error}).");
        }

        try
        {
            var targets = new List<string>(count);
            for (int i = 0; i < count; i++)
            {
                var credPtr = Marshal.ReadIntPtr(credArrayPtr, i * IntPtr.Size);
                var cred = Marshal.PtrToStructure<NativeCredential>(credPtr);
                if (cred.TargetName is not null)
                    targets.Add(cred.TargetName);
            }

            return CredentialStoreResult<IReadOnlyList<string>>.Ok(targets);
        }
        finally
        {
            NativeMethods.CredFree(credArrayPtr);
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NativeCredential
    {
        public uint Flags;
        public int Type;
        public string? TargetName;
        public string? Comment;
        public long LastWritten; // FILETIME (two DWORDs, 8 bytes) — never read, size-matched
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public int Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        public string? TargetAlias;
        public string? UserName;
    }

    private static class NativeMethods
    {
        [DllImport("advapi32.dll", EntryPoint = "CredReadW", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CredRead(string targetName, int type, int flags, out IntPtr credential);

        [DllImport("advapi32.dll", EntryPoint = "CredWriteW", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CredWrite(ref NativeCredential credential, int flags);

        [DllImport("advapi32.dll", EntryPoint = "CredDeleteW", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CredDelete(string targetName, int type, int flags);

        [DllImport("advapi32.dll", EntryPoint = "CredEnumerateW", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CredEnumerate(string? filter, int flags, out int count, out IntPtr credentials);

        [DllImport("advapi32.dll", EntryPoint = "CredFree")]
        public static extern void CredFree(IntPtr buffer);
    }
}
