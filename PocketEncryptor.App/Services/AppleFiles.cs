#if IOS || MACCATALYST
using Foundation;
using PocketEncryptor.Core;
using UIKit;
using UniformTypeIdentifiers;

namespace PocketEncryptor.App.Services;

/// <summary>
/// A file the user picked, opened with the app or dropped on it, used where it
/// is rather than copied, so "Purge" can delete it. The system grants access
/// through a security-scoped URL, held until the app lets go of the file
/// (see <see cref="WorkingFiles.Release"/>).
/// </summary>
internal sealed class AppleOriginal : IOriginalFile, IDisposable
{
    private readonly NSUrl _url;
    private bool _granted;

    private AppleOriginal(NSUrl url)
    {
        _url = url;
        _granted = url.StartAccessingSecurityScopedResource(); // false where no grant is needed
        FullPath = url.Path ?? throw new IOException("That file has no path.");
    }

    public string FullPath { get; }

    public string? WhyNotRemovable =>
        !File.Exists(FullPath) ? "it no longer exists"
        : new FileInfo(FullPath).IsReadOnly ? "it's read-only"
        : null;

    public Task RemoveAsync() => Task.Run(() => SecureFile.OverwriteAndDelete(FullPath));

    public void Dispose()
    {
        if (_granted)
        {
            _granted = false;
            _url.StopAccessingSecurityScopedResource();
        }
    }

    /// <summary>The file at <paramref name="url"/>, read (and for Purge deleted) in place.</summary>
    public static PickedFile Open(NSUrl url)
    {
        var original = new AppleOriginal(url);
        return new PickedFile(new FileResult(original.FullPath), original);
    }

    /// <summary>
    /// A temporary copy the system handed over (e.g. from another app's share
    /// sheet): copied into the app's cache, where it's tidied up like a picker
    /// copy. Its original isn't ours to delete.
    /// </summary>
    /// <param name="deleteSource">The system left the copy in the app's own storage for us to clean up.</param>
    public static PickedFile CopyOf(NSUrl url, bool deleteSource)
    {
        string source = url.Path ?? throw new IOException("That file has no path.");
        string folder = Path.Combine(FileSystem.CacheDirectory, "incoming", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        string copy = Path.Combine(folder, Path.GetFileName(source));
        File.Copy(source, copy);
        if (deleteSource)
        {
            WorkingFiles.TryDelete(source);
        }
        return new PickedFile(new FileResult(copy), Original: null);
    }
}

/// <summary>The iOS / macOS document picker.</summary>
internal static class AppleFilePicker
{
    /// <summary>Lets the user choose files, used in place (not copied).</summary>
    /// <returns>The chosen files; empty if the user cancelled.</returns>
    public static async Task<IReadOnlyList<PickedFile>> PickFilesAsync()
    {
        using var picker = new UIDocumentPickerViewController([UTTypes.Data], asCopy: false) { AllowsMultipleSelection = true };
        NSUrl[] urls = await ShowAsync(picker, CancellationToken.None);
        return [.. urls.Select(AppleOriginal.Open)];
    }

    /// <summary>Shows <paramref name="picker"/>.</summary>
    /// <returns>The chosen URLs; empty if the user cancelled.</returns>
    public static async Task<NSUrl[]> ShowAsync(UIDocumentPickerViewController picker, CancellationToken cancellationToken)
    {
        UIViewController presenter = Platform.GetCurrentUIViewController()
            ?? throw new InvalidOperationException("There's no window to show the picker in.");

        var picked = new TaskCompletionSource<NSUrl[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        picker.DidPickDocumentAtUrls += (_, e) => picked.TrySetResult(e.Urls);
        picker.WasCancelled += (_, _) => picked.TrySetResult([]);

        await using CancellationTokenRegistration registration =
            cancellationToken.Register(() => picked.TrySetCanceled(cancellationToken));
        presenter.PresentViewController(picker, true, null);
        return await picked.Task;
    }
}

/// <summary>
/// Files handed to the app on iOS and macOS: "Open with" in Finder, "Open in"
/// or Share from Files and other apps, and files dropped on the window.
/// </summary>
internal static class AppleIncomingFiles
{
    /// <summary>Handles files opened with the app (scene URL contexts).</summary>
    /// <returns>True if there were files to handle.</returns>
    public static bool Open(NSSet<UIOpenUrlContext>? contexts)
    {
        UIOpenUrlContext[] opened = contexts?.ToArray().Where(c => c.Url.IsFileUrl).ToArray() ?? [];
        if (opened.Length == 0)
        {
            return false;
        }

        var files = new List<PickedFile>(opened.Length);
        int failed = 0;
        foreach (UIOpenUrlContext context in opened)
        {
            try
            {
                files.Add(context.Options.OpenInPlace
                    ? AppleOriginal.Open(context.Url)
                    : AppleOriginal.CopyOf(context.Url, deleteSource: true));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                failed++;
            }
        }

        string? problem = failed == 0 ? null
            : failed == opened.Length ? "Couldn't read the opened files."
            : $"{failed} of the opened files couldn't be read and were left out.";
        if (files.Count > 0)
        {
            IncomingFiles.Deliver(files, problem);
        }
        else
        {
            IncomingFiles.Failed(problem!);
        }
        return true;
    }

    /// <summary>Reads the files dropped on the window, in place where the system allows it.</summary>
    public static async Task<(List<PickedFile> Files, bool HadFolders, int Failed)> ReadDropAsync(IUIDropSession session)
    {
        var files = new List<PickedFile>();
        bool hadFolders = false;
        int failed = 0;
        foreach (UIDragItem item in session.Items)
        {
            NSItemProvider provider = item.ItemProvider;
            if (provider.HasItemConformingTo(UTTypes.Folder.Identifier))
            {
                hadFolders = true;
                continue;
            }
            string? type = provider.RegisteredTypeIdentifiers
                .FirstOrDefault(t => UTType.CreateFromIdentifier(t)?.ConformsTo(UTTypes.Data) == true);
            if (type is not null && await LoadAsync(provider, type) is { } file)
            {
                files.Add(file);
            }
            else
            {
                failed++;
            }
        }
        return (files, hadFolders, failed);
    }

    private static Task<PickedFile?> LoadAsync(NSItemProvider provider, string type)
    {
        var loaded = new TaskCompletionSource<PickedFile?>(TaskCreationOptions.RunContinuationsAsynchronously);
        provider.LoadInPlaceFileRepresentation(type, (url, inPlace, _) =>
        {
            try
            {
                // A copy is deleted as soon as this returns, so take ours right away.
                loaded.TrySetResult(url is null ? null
                    : inPlace ? AppleOriginal.Open(url)
                    : AppleOriginal.CopyOf(url, deleteSource: false));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                loaded.TrySetResult(null);
            }
        });
        return loaded.Task;
    }
}
#endif
