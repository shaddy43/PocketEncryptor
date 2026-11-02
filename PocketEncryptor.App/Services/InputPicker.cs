namespace PocketEncryptor.App.Services;

/// <summary>Shows the platform's "open files" UI.</summary>
internal static class InputPicker
{
    /// <returns>The chosen files; empty if the user cancelled.</returns>
    public static Task<IReadOnlyList<PickedFile>> PickFilesAsync()
    {
#if WINDOWS
        return PickWithShellDialogAsync();
#elif ANDROID
        return Droid.AndroidFilePicker.PickAsync();
#else
        return PickWithMauiAsync();
#endif
    }

#if WINDOWS
    // See WindowsShellDialogs for why not MAUI's FilePicker here.
    private static async Task<IReadOnlyList<PickedFile>> PickWithShellDialogAsync()
    {
        // The dialog is modal and synchronous; let the button's click handler
        // return first so the UI (and screen readers) aren't left waiting on it.
        await Task.Yield();
        return [.. WinUI.WindowsShellDialogs.PickFiles("Choose files").Select(PickedFile.FromPath)];
    }
#elif !ANDROID
    // iOS and macOS: MAUI's picker gives private copies, so the originals
    // can't be deleted from here (yet).
    private static async Task<IReadOnlyList<PickedFile>> PickWithMauiAsync()
    {
        var picked = await FilePicker.Default.PickMultipleAsync(new PickOptions { PickerTitle = "Choose files" });
        return picked?.OfType<FileResult>().Select(file => new PickedFile(file, Original: null)).ToList() ?? [];
    }
#endif
}
