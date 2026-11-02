using Android.Content;
using Android.Provider;
using PocketEncryptor.App.Services;
using AUri = Android.Net.Uri;

namespace PocketEncryptor.App.Droid;

/// <summary>
/// Takes files shared to the app ("Share → PocketEncryptor") or opened with it
/// ("Open with"), copies them into private storage and hands them to the page.
/// </summary>
/// <remarks>
/// The other app's permission to read a shared file only lasts while the
/// activity that received it is alive, so the files are copied right away,
/// the same way the system file picker does. The copies live in the app's
/// private cache and are deleted like picker copies (see WorkingFiles).
/// </remarks>
internal static class AndroidShareReceiver
{
    public static void Handle(Intent? intent)
    {
        if (intent?.Action is not (Intent.ActionSend or Intent.ActionSendMultiple or Intent.ActionView))
        {
            return; // a normal launch
        }
        if (intent.Flags.HasFlag(ActivityFlags.LaunchedFromHistory))
        {
            return; // reopened from Recents: the shared files were already handled
        }

        List<AUri> uris = intent.Action == Intent.ActionView
            ? (intent.Data is { } data ? [data] : [])
            : SharedUris(intent);
        intent.SetAction(Intent.ActionMain); // handle each share once

        if (uris.Count == 0)
        {
            IncomingFiles.Failed("Only files can be shared with PocketEncryptor.");
            return;
        }

        IncomingFiles.Receiving(uris.Count == 1 ? "Receiving the shared file…" : $"Receiving {uris.Count} shared files…");
        ContentResolver resolver = Platform.AppContext.ContentResolver!;
        _ = Task.Run(() =>
        {
            var files = new List<FileResult>(uris.Count);
            int failed = 0;
            foreach (AUri uri in uris)
            {
                try
                {
                    files.Add(new FileResult(CopyToCache(resolver, uri)));
                }
                catch (Exception ex) when (ex is IOException or Java.Lang.Exception or UnauthorizedAccessException)
                {
                    failed++;
                }
            }

            string? problem = failed == 0 ? null
                : failed == uris.Count ? "Couldn't read the shared files."
                : $"{failed} of the shared files couldn't be read and were left out.";
            if (files.Count > 0)
            {
                IncomingFiles.Deliver(files, problem);
            }
            else
            {
                IncomingFiles.Failed(problem!);
            }
        });
    }

    private static List<AUri> SharedUris(Intent intent)
    {
        var uris = new List<AUri>();

        // The system copies EXTRA_STREAM into ClipData, which is also what the
        // read permission is granted on.
        if (intent.ClipData is { } clip)
        {
            for (int i = 0; i < clip.ItemCount; i++)
            {
                if (clip.GetItemAt(i)?.Uri is { } uri)
                {
                    uris.Add(uri);
                }
            }
        }
        if (uris.Count == 0)
        {
#pragma warning disable CA1422, CS0618 // the typed overloads need API 33; these still work everywhere
            if (intent.Action == Intent.ActionSend && intent.GetParcelableExtra(Intent.ExtraStream) is AUri single)
            {
                uris.Add(single);
            }
            else if (intent.GetParcelableArrayListExtra(Intent.ExtraStream) is { } many)
            {
                uris.AddRange(many.OfType<AUri>());
            }
#pragma warning restore CA1422, CS0618
        }
        return uris;
    }

    private static string CopyToCache(ContentResolver resolver, AUri uri)
    {
        string name = SafeFileName(QueryDisplayName(resolver, uri) ?? uri.LastPathSegment);
        string folder = Path.Combine(FileSystem.CacheDirectory, "shared", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        string path = Path.Combine(folder, name);

        using Stream input = resolver.OpenInputStream(uri) ?? throw new IOException("Couldn't open the shared file.");
        using FileStream output = new(path, FileMode.CreateNew, FileAccess.Write);
        input.CopyTo(output);
        return path;
    }

    private static string? QueryDisplayName(ContentResolver resolver, AUri uri)
    {
        try
        {
            using var cursor = resolver.Query(uri, [DocumentsContract.Document.ColumnDisplayName], null, null, null);
            return cursor is not null && cursor.MoveToFirst() ? cursor.GetString(0) : null;
        }
        catch (Java.Lang.Exception)
        {
            return null;
        }
    }

    /// <summary>A plain file name that can't point outside the target folder.</summary>
    private static string SafeFileName(string? name)
    {
        name = Path.GetFileName(name ?? string.Empty);
        foreach (char c in Path.GetInvalidFileNameChars())
        {
            name = name.Replace(c, '_');
        }
        return string.IsNullOrWhiteSpace(name) || name is "." or ".." ? "shared file" : name;
    }
}
