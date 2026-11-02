namespace PocketEncryptor.App.Services;

/// <summary>The save was refused for the user's protection; the message says why.</summary>
internal sealed class SaveRefusedException(string message) : Exception(message);

/// <summary>A folder the user chose for a batch of results.</summary>
internal interface IOutputFolder
{
    /// <summary>How to refer to the folder in messages.</summary>
    string DisplayName { get; }

    /// <summary>
    /// Saves a finished result into the folder. Never replaces an existing file:
    /// if <paramref name="fileName"/> is taken, a numbered name is used.
    /// </summary>
    /// <returns>The name it was saved under, or null if the user skipped it.</returns>
    Task<string?> SaveAsync(string tempPath, string fileName, CancellationToken cancellationToken);
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
        return saved.FilePath;
#endif
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

#if !WINDOWS && !ANDROID
    /// <summary>
    /// iOS and macOS for now: one Save dialog per file. A real folder picker there
    /// needs security-scoped folder access, which is still to be built on a Mac.
    /// </summary>
    private sealed class SaveEachFile : IOutputFolder
    {
        public string DisplayName => "the locations you chose";

        public async Task<string?> SaveAsync(string tempPath, string fileName, CancellationToken cancellationToken)
        {
            string? saved = await OutputSaver.SaveAsync(tempPath, fileName, sourcePath: null, cancellationToken);
            return saved is null ? null : Path.GetFileName(saved);
        }
    }
#endif
}
