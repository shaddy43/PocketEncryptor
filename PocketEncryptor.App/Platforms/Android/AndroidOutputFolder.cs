using Android.App;
using Android.Content;
using Android.Provider;
using Android.Webkit;
using PocketEncryptor.App.Services;
using PocketEncryptor.Core;
using AUri = Android.Net.Uri;

// Not "...Platforms.Android": that would shadow the global Android.* namespaces.
namespace PocketEncryptor.App.Droid;

/// <summary>
/// A folder chosen with the system folder picker (Storage Access Framework).
/// </summary>
/// <remarks>
/// Files are created through the document provider, so this works for any
/// folder the user grants (internal storage, SD card, Drive, ...). Android
/// itself won't offer the root of Download or of the storage; the picker lets
/// the user create or choose a subfolder instead.
/// </remarks>
internal sealed class AndroidOutputFolder : IOutputFolder
{
    private const int RequestCode = 0x504B; // "PK"
    private static TaskCompletionSource<AUri?>? s_pending;

    private readonly AUri _folderUri;
    private readonly AUri _childrenUri;

    private AndroidOutputFolder(AUri treeUri)
    {
        string folderId = DocumentsContract.GetTreeDocumentId(treeUri)
            ?? throw new IOException("Couldn't open that folder.");
        _folderUri = DocumentsContract.BuildDocumentUriUsingTree(treeUri, folderId)
            ?? throw new IOException("Couldn't open that folder.");
        _childrenUri = DocumentsContract.BuildChildDocumentsUriUsingTree(treeUri, folderId)
            ?? throw new IOException("Couldn't open that folder.");
        DisplayName = QueryDisplayName(_folderUri) ?? "the chosen folder";
    }

    public string DisplayName { get; }

    public static async Task<IOutputFolder?> PickAsync(CancellationToken cancellationToken)
    {
        Activity activity = Platform.CurrentActivity ?? throw new InvalidOperationException("The app isn't in the foreground.");

        var pending = new TaskCompletionSource<AUri?>(TaskCreationOptions.RunContinuationsAsynchronously);
        Interlocked.Exchange(ref s_pending, pending)?.TrySetResult(null);

        var intent = new Intent(Intent.ActionOpenDocumentTree);
        intent.AddFlags(ActivityFlags.GrantReadUriPermission | ActivityFlags.GrantWriteUriPermission);
        activity.StartActivityForResult(intent, RequestCode);

        using (cancellationToken.Register(() => pending.TrySetCanceled()))
        {
            AUri? treeUri = await pending.Task;
            return treeUri is null ? null : new AndroidOutputFolder(treeUri);
        }
    }

    /// <summary>Wired up in MauiProgram through the Android lifecycle events.</summary>
    internal static void OnActivityResult(Activity activity, int requestCode, Result resultCode, Intent? data)
    {
        if (requestCode == RequestCode)
        {
            Interlocked.Exchange(ref s_pending, null)?.TrySetResult(resultCode == Result.Ok ? data?.Data : null);
        }
    }

    public Task<string?> SaveAsync(string tempPath, string fileName, CancellationToken cancellationToken) =>
        Task.Run<string?>(async () =>
        {
            ContentResolver resolver = Platform.AppContext.ContentResolver!;

            // Pick a free name ourselves, numbered the same way as on the other
            // platforms. (The provider would also avoid a clash, but its
            // "photo.jpg (1).pkec" decrypts to an awkward "photo.jpg (1)".)
            fileName = FreeName(resolver, fileName);
            AUri document = DocumentsContract.CreateDocument(resolver, _folderUri, MimeTypeFor(fileName), fileName)
                ?? throw new IOException("Couldn't create a file in that folder.");
            try
            {
                await using (Stream output = resolver.OpenOutputStream(document, "w")
                    ?? throw new IOException("Couldn't write to that folder."))
                await using (FileStream input = File.OpenRead(tempPath))
                {
                    await input.CopyToAsync(output, cancellationToken);
                }
            }
            catch
            {
                TryDelete(resolver, document); // no half-written files
                throw;
            }
            return QueryDisplayName(document) ?? fileName;
        }, cancellationToken);

    /// <summary>"photo.jpg.pkec", or "photo (1).jpg.pkec" etc. if that's taken.</summary>
    private string FreeName(ContentResolver resolver, string fileName)
    {
        var taken = new HashSet<string>(StringComparer.OrdinalIgnoreCase); // shared storage ignores case
        try
        {
            using var cursor = resolver.Query(_childrenUri, [DocumentsContract.Document.ColumnDisplayName], null, null, null);
            while (cursor is not null && cursor.MoveToNext())
            {
                if (cursor.GetString(0) is { } name)
                {
                    taken.Add(name);
                }
            }
        }
        catch (Java.Lang.Exception)
        {
            return fileName; // can't list the folder; the provider still avoids clashes
        }

        string candidate = fileName;
        for (int counter = 1; taken.Contains(candidate); counter++)
        {
            candidate = OutputFiles.WithCounter(fileName, counter);
        }
        return candidate;
    }

    private static string MimeTypeFor(string fileName)
    {
        string extension = Path.GetExtension(fileName).TrimStart('.').ToLowerInvariant();
        return (extension.Length > 0 ? MimeTypeMap.Singleton?.GetMimeTypeFromExtension(extension) : null)
            ?? "application/octet-stream";
    }

    private static string? QueryDisplayName(AUri uri)
    {
        try
        {
            using var cursor = Platform.AppContext.ContentResolver!.Query(
                uri, [DocumentsContract.Document.ColumnDisplayName], null, null, null);
            return cursor is not null && cursor.MoveToFirst() ? cursor.GetString(0) : null;
        }
        catch (Java.Lang.Exception)
        {
            return null;
        }
    }

    private static void TryDelete(ContentResolver resolver, AUri document)
    {
        try
        {
            DocumentsContract.DeleteDocument(resolver, document);
        }
        catch (Java.Lang.Exception)
        {
            // Best effort.
        }
    }
}
