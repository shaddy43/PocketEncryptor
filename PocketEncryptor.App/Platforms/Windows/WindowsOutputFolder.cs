using PocketEncryptor.App.Services;
using PocketEncryptor.Core;

namespace PocketEncryptor.App.WinUI;

/// <summary>A folder chosen with the Windows Select Folder dialog.</summary>
internal sealed class WindowsOutputFolder(string path) : IOutputFolder
{
    public string DisplayName => path;

    public static async Task<IOutputFolder?> PickAsync(CancellationToken cancellationToken)
    {
        await Task.Yield(); // the dialog is modal and synchronous; let the click handler return first
        string? folder = WindowsShellDialogs.PickFolder("Choose a folder for the results");
        cancellationToken.ThrowIfCancellationRequested();
        if (folder is null)
        {
            return null;
        }
        if (!Directory.Exists(folder))
        {
            throw new SaveRefusedException("Can't save into that location. Choose a regular folder.");
        }
        return new WindowsOutputFolder(folder);
    }

    public Task<string?> SaveAsync(string tempPath, string fileName, CancellationToken cancellationToken) =>
        Task.Run<string?>(() => Path.GetFileName(OutputFiles.CopyIntoFolder(tempPath, path, fileName)), cancellationToken);
}
