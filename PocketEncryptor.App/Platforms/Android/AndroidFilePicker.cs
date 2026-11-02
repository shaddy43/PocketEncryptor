using Android.Content;
using Android.Provider;
using PocketEncryptor.App.Services;
using PocketEncryptor.Core;
using AUri = Android.Net.Uri;

namespace PocketEncryptor.App.Droid;

/// <summary>
/// The system "open files" picker, keeping a handle on each original.
/// </summary>
/// <remarks>
/// MAUI's FilePicker hands back only a private copy. Asking the picker for
/// read and write access ourselves keeps the document's address, so the
/// original can be deleted later if the user ticks "Purge" and the app
/// holding it (e.g. Files, Downloads) allows it.
/// </remarks>
internal static class AndroidFilePicker
{
    public static async Task<IReadOnlyList<PickedFile>> PickAsync()
    {
        var intent = new Intent(Intent.ActionOpenDocument);
        intent.AddCategory(Intent.CategoryOpenable);
        intent.SetType("*/*");
        intent.PutExtra(Intent.ExtraAllowMultiple, true);
        intent.AddFlags(ActivityFlags.GrantReadUriPermission | ActivityFlags.GrantWriteUriPermission);

        Intent? result = await AndroidActivityResults.StartAsync(intent);
        List<AUri> uris = AndroidDocuments.UrisIn(result);
        if (uris.Count == 0)
        {
            return [];
        }

        // Copy each file into private storage, like MAUI's picker does.
        return await Task.Run(() => uris
            .Select(uri => new PickedFile(new FileResult(AndroidDocuments.CopyToCache(uri)), new AndroidDocumentOriginal(uri)))
            .ToList());
    }
}

/// <summary>An original the user picked, addressed by its document URI.</summary>
internal sealed class AndroidDocumentOriginal(AUri uri) : IOriginalFile
{
    public string? WhyNotRemovable =>
        (AndroidDocuments.QueryFlags(uri) & (int)DocumentContractFlags.SupportsDelete) != 0
            ? null
            : "the app it's stored in doesn't allow deleting it";

    public Task RemoveAsync() => Task.Run(() =>
    {
        // Best effort: overwrite the contents in place before deleting.
        // ("rw" keeps the existing data blocks; "rwt" would truncate first.)
        try
        {
            if (AndroidDocuments.QuerySize(uri) is > 0 and long size)
            {
                using Stream? stream = AndroidDocuments.Resolver.OpenOutputStream(uri, "rw");
                if (stream is not null)
                {
                    SecureFile.Overwrite(stream, size);
                }
            }
        }
        catch (Exception ex) when (ex is IOException or Java.Lang.Exception or UnauthorizedAccessException)
        {
            // Some providers don't allow writing; deleting still goes ahead.
        }

        if (!DocumentsContract.DeleteDocument(AndroidDocuments.Resolver, uri))
        {
            throw new IOException("Android didn't delete the original.");
        }
    });
}
