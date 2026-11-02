using Android.Content;
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
/// Shared files are read-only to us, so their originals can't be deleted.
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
        _ = Task.Run(() =>
        {
            var files = new List<PickedFile>(uris.Count);
            int failed = 0;
            foreach (AUri uri in uris)
            {
                try
                {
                    files.Add(new PickedFile(new FileResult(AndroidDocuments.CopyToCache(uri)), Original: null));
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
        // The system copies EXTRA_STREAM into ClipData, which is also what the
        // read permission is granted on.
        List<AUri> uris = AndroidDocuments.UrisIn(intent);
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
}
