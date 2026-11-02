namespace PocketEncryptor.App.Services;

/// <summary>
/// Forwards progress from a background thread to the UI thread at most ~10
/// times a second. (A 1 GB file is ~16,000 chunks; posting every one of them
/// would flood the UI thread.)
/// </summary>
internal sealed class ThrottledProgress(Action<long> onUiThread) : IProgress<long>
{
    private const long IntervalMs = 100;
    private long _lastReport = long.MinValue / 2;

    public void Report(long value)
    {
        long now = Environment.TickCount64;
        if (now - Interlocked.Read(ref _lastReport) < IntervalMs)
        {
            return;
        }
        Interlocked.Exchange(ref _lastReport, now);
        MainThread.BeginInvokeOnMainThread(() => onUiThread(value));
    }
}
