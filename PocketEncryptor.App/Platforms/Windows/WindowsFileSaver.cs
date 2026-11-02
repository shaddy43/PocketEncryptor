using System.Diagnostics;
using PocketEncryptor.App.Services;
using Windows.Storage.Pickers;
using WinRT.Interop;

// Not "...Platforms.Windows": that would shadow the global Windows.* namespaces.
namespace PocketEncryptor.App.WinUI;

/// <summary>
/// Windows "Save as" dialog.
/// </summary>
/// <remarks>
/// Replaces CommunityToolkit's FileSaver on Windows. That one passes the name
/// without its last extension plus a separate file-type filter (".pkec"), and
/// the Windows picker won't append the filter's extension to a name that already
/// has one, so saving "photo.jpg.pkec" would actually target "photo.jpg", the
/// user's original file. Here the full name is suggested with an "All files"
/// filter, so what the user sees is exactly what gets written.
/// </remarks>
internal static class WindowsFileSaver
{
    public static async Task<string?> SaveAsync(string tempPath, string suggestedName, string? sourcePath,
        CancellationToken cancellationToken)
    {
        var picker = new FileSavePicker
        {
            SuggestedStartLocation = PickerLocationId.DocumentsLibrary,
            SuggestedFileName = suggestedName,
        };
        picker.FileTypeChoices.Add("All files", new List<string> { "." });

        InitializeWithWindow.Initialize(picker, GetWindowHandle());

        var file = await picker.PickSaveFileAsync();
        if (file is null || string.IsNullOrEmpty(file.Path))
        {
            return null; // cancelled
        }
        cancellationToken.ThrowIfCancellationRequested();

        string destination = Path.GetFullPath(file.Path);
        if (sourcePath is not null &&
            string.Equals(destination, Path.GetFullPath(sourcePath), StringComparison.OrdinalIgnoreCase))
        {
            throw new SaveRefusedException(
                "That would replace the original file. Choose a different name or folder.");
        }

        // Copy next to the destination first, then swap it in, so a file the
        // user chose to replace is never left half-written.
        string staging = Path.Combine(Path.GetDirectoryName(destination)!,
            "." + Path.GetFileName(destination) + "." + Guid.NewGuid().ToString("N")[..8] + ".tmp");
        try
        {
            await Task.Run(() =>
            {
                File.Copy(tempPath, staging);
                File.Move(staging, destination, overwrite: true);
            }, cancellationToken);
        }
        catch
        {
            WorkingFiles.TryDelete(staging);
            throw;
        }
        return destination;
    }

    private static IntPtr GetWindowHandle()
    {
        if (Application.Current?.Windows.FirstOrDefault()?.Handler?.PlatformView is Microsoft.UI.Xaml.Window window)
        {
            return WindowNative.GetWindowHandle(window);
        }
        return Process.GetCurrentProcess().MainWindowHandle;
    }
}
