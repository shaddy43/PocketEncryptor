namespace PocketEncryptor.App.Services;

/// <summary>A status line about incoming files.</summary>
internal sealed record IncomingNotice(string Text, bool IsError);

/// <summary>
/// Files handed to the app from outside: the share sheet and "Open with" on
/// Android, iOS and macOS, or the command line on Windows. Platform code
/// delivers them here; the main page takes them when it's ready.
/// </summary>
internal static class IncomingFiles
{
    private static IReadOnlyList<PickedFile>? s_pending;
    private static IncomingNotice? s_notice;

    /// <summary>Raised on the main thread when files or a notice arrive.</summary>
    public static event Action? Changed;

    /// <summary>Files are on their way (e.g. being copied from another app).</summary>
    public static void Receiving(string message) => Post(() => s_notice = new IncomingNotice(message, IsError: false));

    /// <summary>Nothing usable arrived; tell the user why.</summary>
    public static void Failed(string message) => Post(() => s_notice = new IncomingNotice(message, IsError: true));

    /// <param name="problem">Shown as an error alongside the files, e.g. some couldn't be read.</param>
    public static void Deliver(IReadOnlyList<PickedFile> files, string? problem = null)
    {
        if (files.Count == 0)
        {
            return;
        }
        Post(() =>
        {
            // Files nobody took yet are replaced; let go of them.
            foreach (PickedFile old in s_pending ?? [])
            {
                WorkingFiles.Release(old.File, old.Original);
            }
            s_pending = files;
            s_notice = problem is null ? null : new IncomingNotice(problem, IsError: true);
        });
    }

    /// <summary>Takes the files waiting to be loaded, if any.</summary>
    public static IReadOnlyList<PickedFile>? TakeFiles() => Interlocked.Exchange(ref s_pending, null);

    /// <summary>Takes the latest notice, if any.</summary>
    public static IncomingNotice? TakeNotice() => Interlocked.Exchange(ref s_notice, null);

    private static void Post(Action update) => MainThread.BeginInvokeOnMainThread(() =>
    {
        update();
        Changed?.Invoke();
    });
}
