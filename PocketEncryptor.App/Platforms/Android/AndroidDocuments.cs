using Android.App;
using Android.Content;
using Android.Provider;
using Android.Webkit;
using AUri = Android.Net.Uri;

namespace PocketEncryptor.App.Droid;

/// <summary>Helpers for content:// documents (Storage Access Framework).</summary>
internal static class AndroidDocuments
{
    public static ContentResolver Resolver => Platform.AppContext.ContentResolver!;

    public static string? QueryDisplayName(AUri uri) =>
        Query(uri, DocumentsContract.Document.ColumnDisplayName, c => c.GetString(0));

    public static long? QuerySize(AUri uri) =>
        Query(uri, DocumentsContract.Document.ColumnSize, c => c.IsNull(0) ? (long?)null : c.GetLong(0));

    /// <summary>DocumentsContract.Document flags, or 0 if the provider doesn't say.</summary>
    public static int QueryFlags(AUri uri) =>
        Query(uri, DocumentsContract.Document.ColumnFlags, c => c.IsNull(0) ? 0 : c.GetInt(0));

    /// <summary>
    /// Copies a document into a new folder in the app's private cache and
    /// returns the copy's path. The copy is deleted like a picker copy
    /// (see WorkingFiles.DeletePickerCopy).
    /// </summary>
    public static string CopyToCache(AUri uri)
    {
        string name = SafeFileName(QueryDisplayName(uri) ?? uri.LastPathSegment);
        string folder = Path.Combine(FileSystem.CacheDirectory, "picked", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        string path = Path.Combine(folder, name);

        using Stream input = Resolver.OpenInputStream(uri) ?? throw new IOException("Couldn't open the file.");
        using FileStream output = new(path, FileMode.CreateNew, FileAccess.Write);
        input.CopyTo(output);
        return path;
    }

    public static string MimeTypeFor(string fileName)
    {
        string extension = Path.GetExtension(fileName).TrimStart('.').ToLowerInvariant();
        return (extension.Length > 0 ? MimeTypeMap.Singleton?.GetMimeTypeFromExtension(extension) : null)
            ?? "application/octet-stream";
    }

    public static void TryDelete(AUri document)
    {
        try
        {
            DocumentsContract.DeleteDocument(Resolver, document);
        }
        catch (Java.Lang.Exception)
        {
            // Best effort.
        }
    }

    /// <summary>The documents in a picker result (one, or several with ClipData).</summary>
    public static List<AUri> UrisIn(Intent? data)
    {
        var uris = new List<AUri>();
        if (data?.ClipData is { } clip)
        {
            for (int i = 0; i < clip.ItemCount; i++)
            {
                if (clip.GetItemAt(i)?.Uri is { } uri)
                {
                    uris.Add(uri);
                }
            }
        }
        if (uris.Count == 0 && data?.Data is { } single)
        {
            uris.Add(single);
        }
        return uris;
    }

    /// <summary>A plain file name that can't point outside the target folder.</summary>
    private static string SafeFileName(string? name)
    {
        name = Path.GetFileName(name ?? string.Empty);
        foreach (char c in Path.GetInvalidFileNameChars())
        {
            name = name.Replace(c, '_');
        }
        return string.IsNullOrWhiteSpace(name) || name is "." or ".." ? "file" : name;
    }

    private static T? Query<T>(AUri uri, string column, Func<Android.Database.ICursor, T> read)
    {
        try
        {
            using var cursor = Resolver.Query(uri, [column], null, null, null);
            return cursor is not null && cursor.MoveToFirst() ? read(cursor) : default;
        }
        catch (Java.Lang.Exception)
        {
            return default;
        }
    }
}

/// <summary>
/// Starts activities for a result and awaits it (system pickers).
/// Results arrive through the lifecycle event wired up in MauiProgram.
/// </summary>
internal static class AndroidActivityResults
{
    private static readonly Dictionary<int, TaskCompletionSource<Intent?>> s_pending = [];
    private static int s_counter;

    /// <returns>The result data, or null if the user cancelled.</returns>
    public static async Task<Intent?> StartAsync(Intent intent, CancellationToken cancellationToken = default)
    {
        Activity activity = Platform.CurrentActivity ?? throw new InvalidOperationException("The app isn't in the foreground.");

        // Request codes must fit in 16 bits; keep ours in 0x5000-0x5FFF.
        int code = 0x5000 + (Interlocked.Increment(ref s_counter) & 0xFFF);
        var pending = new TaskCompletionSource<Intent?>(TaskCreationOptions.RunContinuationsAsynchronously);
        lock (s_pending)
        {
            s_pending[code] = pending;
        }

        activity.StartActivityForResult(intent, code);
        using (cancellationToken.Register(() => pending.TrySetCanceled()))
        {
            return await pending.Task;
        }
    }

    internal static void OnActivityResult(Activity activity, int requestCode, Result resultCode, Intent? data)
    {
        TaskCompletionSource<Intent?>? pending;
        lock (s_pending)
        {
            s_pending.Remove(requestCode, out pending);
        }
        pending?.TrySetResult(resultCode == Result.Ok ? data : null);
    }
}
