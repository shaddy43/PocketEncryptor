namespace PocketEncryptor.App.Services;

/// <summary>
/// Scratch space for results before the user saves them, and cleanup of any
/// plaintext copies the OS leaves in the app's private storage.
/// </summary>
/// <remarks>
/// The result is produced in full (and, for decryption, fully authenticated)
/// before the Save dialog opens, so a wrong password or a damaged file never
/// reaches the user's chosen location. The temp copy is deleted straight after.
/// </remarks>
internal static class WorkingFiles
{
    private static string WorkRoot => Path.Combine(FileSystem.CacheDirectory, "pkec-work");

    /// <summary>
    /// Whether the OS cache and temp folders belong to this app alone: always on
    /// Android and iOS, on macOS only inside the App Sandbox. Without the sandbox
    /// they're the user's shared ~/Library/Caches and $TMPDIR, never to be emptied.
    /// </summary>
    private static bool HasPrivateStorage => OperatingSystem.IsMacCatalyst()
        ? Environment.GetEnvironmentVariable("APP_SANDBOX_CONTAINER_ID") is not null
        : OperatingSystem.IsAndroid() || OperatingSystem.IsIOS();

    public static string NewTempPath()
    {
        Directory.CreateDirectory(WorkRoot);
        return Path.Combine(WorkRoot, Guid.NewGuid().ToString("N") + ".tmp");
    }

    public static void TryDelete(string? path)
    {
        try
        {
            if (path is not null && File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
            // Best effort; CleanUpLeftovers retries on the next launch.
        }
    }

    /// <summary>
    /// Lets go of a file the app no longer lists: deletes its private copy (see
    /// <see cref="DeletePickerCopy"/>) and ends any access granted to its original.
    /// </summary>
    public static void Release(FileResult file, IOriginalFile? original)
    {
        DeletePickerCopy(file);
        (original as IDisposable)?.Dispose();
    }

    /// <summary>
    /// Called at startup: removes files left behind if the app was killed
    /// mid-operation. With <see cref="HasPrivateStorage"/> this also clears picker copies (see
    /// <see cref="DeletePickerCopy"/>), since nothing else in our private
    /// cache is worth keeping.
    /// </summary>
    public static void CleanUpLeftovers()
    {
        IEnumerable<string> roots = HasPrivateStorage
            ? [FileSystem.CacheDirectory, Path.GetTempPath()]
            : [WorkRoot];

        foreach (string root in roots.Distinct())
        {
            try
            {
                if (!Directory.Exists(root))
                {
                    continue;
                }
                foreach (string file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
                {
                    TryDelete(file);
                }
            }
            catch
            {
                // Best effort.
            }
        }
    }

    /// <summary>
    /// On Android and iOS the system picker gives the app a <em>copy</em> of the
    /// chosen file inside its private cache/tmp folder. When that copy is a
    /// plaintext file we've just encrypted, don't leave it lying around.
    /// Only ever deletes files inside the app's own private folders.
    /// </summary>
    /// <param name="overwrite">Overwrite the copy's contents first (best effort), e.g. when the original is being deleted too.</param>
    public static void DeletePickerCopy(FileResult? file, bool overwrite = false)
    {
        if (file is null || !HasPrivateStorage || string.IsNullOrEmpty(file.FullPath))
        {
            return;
        }

        string path = ResolveSymlinks(file.FullPath);
        foreach (string root in new[] { FileSystem.CacheDirectory, Path.GetTempPath() })
        {
            string prefix = Path.TrimEndingDirectorySeparator(ResolveSymlinks(root)) + Path.DirectorySeparatorChar;
            if (path.StartsWith(prefix, StringComparison.Ordinal))
            {
                if (overwrite)
                {
                    try
                    {
                        Core.SecureFile.OverwriteAndDelete(path);
                        return;
                    }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                    {
                        // Fall back to a plain delete.
                    }
                }
                TryDelete(path);
                return;
            }
        }
    }

    /// <summary>
    /// Resolves symlinks anywhere in <paramref name="path"/>, like POSIX realpath.
    /// The same private folder has more than one spelling (Android's
    /// /data/user/0 → /data/data, iOS's /var → /private/var), and the picker and
    /// <see cref="FileSystem.CacheDirectory"/> don't always use the same one.
    /// </summary>
    private static string ResolveSymlinks(string path)
    {
        string full = Path.GetFullPath(path);
        string current = Path.GetPathRoot(full) ?? string.Empty;
        foreach (string part in full[current.Length..].Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, part);
            try
            {
                if (new FileInfo(current).ResolveLinkTarget(returnFinalTarget: true) is { } target)
                {
                    current = target.FullName;
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Can't inspect this component (e.g. a system folder); keep it as written.
            }
        }
        return current;
    }
}
