#if IOS || MACCATALYST
using Foundation;
using PocketEncryptor.Core;
using UIKit;
using UniformTypeIdentifiers;

namespace PocketEncryptor.App.Services;

/// <summary>
/// A folder chosen with the iOS / macOS document picker. Used for single files
/// too: we write the result ourselves, numbered if the name is taken, instead
/// of handing it to the system Save sheet, whose "Keep Both" replaced the
/// existing file on iOS 27.
/// </summary>
/// <remarks>
/// The picker grants access through a security-scoped URL, opened around each
/// use. Outside the App Sandbox (macOS only) it's an ordinary path.
/// </remarks>
internal sealed class AppleOutputFolder : IOutputFolder
{
    private readonly NSUrl _url;
    private readonly string _path;

    private AppleOutputFolder(NSUrl url)
    {
        _url = url;
        _path = url.Path ?? throw new IOException("Couldn't open that folder.");
        // iOS paths are long and internal; its folder name is what Files shows.
        DisplayName = OperatingSystem.IsMacCatalyst() ? _path : LocalizedName(url) ?? Path.GetFileName(_path);
    }

    public string DisplayName { get; }

    /// <returns>The folder, or null if the user cancelled.</returns>
    public static async Task<IOutputFolder?> PickAsync(CancellationToken cancellationToken)
    {
        using var picker = new UIDocumentPickerViewController([UTTypes.Folder]) { AllowsMultipleSelection = false };
        NSUrl[] urls = await AppleFilePicker.ShowAsync(picker, cancellationToken);
        return urls.Length == 0 ? null : new AppleOutputFolder(urls[0]);
    }

    public Task<SavedOutput?> SaveAsync(string tempPath, string fileName, CancellationToken cancellationToken) =>
        Task.Run<SavedOutput?>(() =>
        {
            string saved = WithAccess(() => OutputFiles.CopyIntoFolder(tempPath, _path, fileName));
            return new SavedOutput(
                Path.GetFileName(saved),
                OpenRead: () => WithAccess<Stream>(() => File.OpenRead(saved)), // stays readable once opened
                Delete: () => WithAccess(() => File.Delete(saved)));
        }, cancellationToken);

    private T WithAccess<T>(Func<T> action)
    {
        bool granted = _url.StartAccessingSecurityScopedResource(); // false outside the sandbox
        try
        {
            return action();
        }
        finally
        {
            if (granted)
            {
                _url.StopAccessingSecurityScopedResource();
            }
        }
    }

    private void WithAccess(Action action) => WithAccess(() =>
    {
        action();
        return true;
    });

    private static string? LocalizedName(NSUrl url) =>
        url.TryGetResource(NSUrl.LocalizedNameKey, out NSObject? name) ? name?.ToString() : null;
}
#endif
