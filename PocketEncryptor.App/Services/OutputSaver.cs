namespace PocketEncryptor.App.Services;

/// <summary>The save was refused for the user's protection; the message says why.</summary>
internal sealed class SaveRefusedException(string message) : Exception(message);

/// <summary>
/// Shows the platform's native "Save as" UI and copies a finished result there.
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
}
