namespace PocketEncryptor.App.Services;

/// <summary>Shows the platform's "open files" UI.</summary>
internal static class InputPicker
{
    /// <returns>The chosen files; empty if the user cancelled.</returns>
    public static Task<IReadOnlyList<FileResult>> PickFilesAsync()
    {
#if WINDOWS
        return PickWithShellDialogAsync();
#else
        return PickWithMauiAsync();
#endif
    }

#if WINDOWS
    // See WindowsShellDialogs for why not MAUI's FilePicker here.
    private static async Task<IReadOnlyList<FileResult>> PickWithShellDialogAsync()
    {
        // The dialog is modal and synchronous; let the button's click handler
        // return first so the UI (and screen readers) aren't left waiting on it.
        await Task.Yield();
        return [.. WinUI.WindowsShellDialogs.PickFiles("Choose files").Select(path => new FileResult(path))];
    }
#else
    private static async Task<IReadOnlyList<FileResult>> PickWithMauiAsync()
    {
        var picked = await FilePicker.Default.PickMultipleAsync(new PickOptions { PickerTitle = "Choose files" });
        return picked?.OfType<FileResult>().ToList() ?? [];
    }
#endif
}
