namespace PocketEncryptor.App.Services;

/// <summary>The save was refused for the user's protection; the message says why.</summary>
internal sealed class SaveRefusedException(string message) : Exception(message);

/// <summary>A result saved into an output folder.</summary>
/// <param name="Name">The name it was saved under.</param>
/// <param name="OpenRead">Reads the saved file back (to check it before deleting an original).</param>
/// <param name="Delete">Removes it again, e.g. if that check fails.</param>
internal sealed record SavedOutput(string Name, Func<Stream> OpenRead, Action Delete);

/// <summary>A folder the user chose for a batch of results.</summary>
internal interface IOutputFolder
{
    /// <summary>How to refer to the folder in messages.</summary>
    string DisplayName { get; }

    /// <summary>
    /// Saves a finished result into the folder. Never replaces an existing file:
    /// if <paramref name="fileName"/> is taken, a numbered name is used.
    /// </summary>
    /// <returns>The saved file, or null if the user skipped it.</returns>
    Task<SavedOutput?> SaveAsync(string tempPath, string fileName, CancellationToken cancellationToken);
}

/// <summary>
/// Shows the platform's native "Save as" / folder UI and copies finished results there.
/// </summary>
internal static class OutputSaver
{
    /// <param name="tempPath">The finished result in private temp storage.</param>
    /// <param name="suggestedName">File name to pre-fill.</param>
    /// <param name="sourcePath">The file that was encrypted/decrypted; never overwritten.</param>
    /// <returns>Where the file was saved, or null if the user cancelled.</returns>
    public static async Task<string?> SaveAsync(string tempPath, string suggestedName, string? sourcePath,
        CancellationToken cancellationToken)
    {
#if WINDOWS
        return await WinUI.WindowsFileSaver.SaveAsync(tempPath, suggestedName, sourcePath, cancellationToken);
#else
        // Android (Storage Access Framework), iOS and macOS (document picker) take the
        // full name as-is and never silently replace a different file. On mobile,
        // sourcePath is the picker's private copy, so it can't be a target anyway.
        await using Stream result = File.OpenRead(tempPath);
        var saved = await CommunityToolkit.Maui.Storage.FileSaver.Default.SaveAsync(suggestedName, result, cancellationToken);
        if (saved.IsCancelled)
        {
            return null;
        }
        saved.EnsureSuccess();
        return Tidy(saved.FilePath);
#endif
    }

    /// <summary>
    /// The toolkit reports Downloads files on Android as
    /// "/storage/raw//storage/emulated/0/Download/x"; show the real path.
    /// </summary>
    private static string? Tidy(string? path)
    {
        int real = path?.IndexOf("//storage/", StringComparison.Ordinal) ?? -1;
        return real >= 0 ? path![(real + 1)..] : path;
    }

    /// <summary>Asks the user for a folder to save a batch of results into.</summary>
    /// <returns>The folder, or null if the user cancelled.</returns>
    public static Task<IOutputFolder?> PickFolderAsync(CancellationToken cancellationToken)
    {
#if WINDOWS
        return WinUI.WindowsOutputFolder.PickAsync(cancellationToken);
#elif ANDROID
        return Droid.AndroidOutputFolder.PickAsync(cancellationToken);
#else
        return Task.FromResult<IOutputFolder?>(new SaveEachFile());
#endif
    }

    /// <summary>
    /// Where "Purge" can put the encrypted file
    /// right next to the original without asking: on Windows, the original's
    /// own folder. Null elsewhere (the user chooses a folder instead).
    /// </summary>
    public static IOutputFolder? FolderOfOriginal(IOriginalFile? original)
    {
#if WINDOWS
        return original is PathOriginal path ? new WinUI.WindowsOutputFolder(Path.GetDirectoryName(path.FullPath)!) : null;
#else
        return null;
#endif
    }

#if !WINDOWS && !ANDROID
    /// <summary>
    /// iOS and macOS for now: one Save dialog per file. A real folder picker there
    /// needs security-scoped folder access, which is still to be built on a Mac.
    /// </summary>
    private sealed class SaveEachFile : IOutputFolder
    {
        public string DisplayName => "the locations you chose";

        public async Task<SavedOutput?> SaveAsync(string tempPath, string fileName, CancellationToken cancellationToken)
        {
            string? saved = await OutputSaver.SaveAsync(tempPath, fileName, sourcePath: null, cancellationToken);
            return saved is null ? null : new SavedOutput(Path.GetFileName(saved), () => File.OpenRead(saved), () => File.Delete(saved));
        }
    }
#endif
}
