using Android.Content;
using Android.Provider;
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
        DisplayName = AndroidDocuments.QueryDisplayName(_folderUri) ?? "the chosen folder";
    }

    public string DisplayName { get; }

    public static async Task<IOutputFolder?> PickAsync(CancellationToken cancellationToken)
    {
        var intent = new Intent(Intent.ActionOpenDocumentTree);
        intent.AddFlags(ActivityFlags.GrantReadUriPermission | ActivityFlags.GrantWriteUriPermission);
        Intent? result = await AndroidActivityResults.StartAsync(intent, cancellationToken);
        return result?.Data is { } treeUri ? new AndroidOutputFolder(treeUri) : null;
    }

    public Task<SavedOutput?> SaveAsync(string tempPath, string fileName, CancellationToken cancellationToken) =>
        Task.Run<SavedOutput?>(async () =>
        {
            ContentResolver resolver = AndroidDocuments.Resolver;

            // Pick a free name ourselves, numbered the same way as on the other
            // platforms. (The provider would also avoid a clash, but its
            // "photo.jpg (1).pkec" decrypts to an awkward "photo.jpg (1)".)
            fileName = FreeName(resolver, fileName);
            AUri document = DocumentsContract.CreateDocument(resolver, _folderUri, AndroidDocuments.MimeTypeFor(fileName), fileName)
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
                AndroidDocuments.TryDelete(document); // no half-written files
                throw;
            }

            return new SavedOutput(
                AndroidDocuments.QueryDisplayName(document) ?? fileName,
                OpenRead: () => resolver.OpenInputStream(document) ?? throw new IOException("Couldn't read the saved file."),
                Delete: () => AndroidDocuments.TryDelete(document));
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
}
