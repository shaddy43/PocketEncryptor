using System.Security.Cryptography;

namespace PocketEncryptor.Core;

/// <summary>
/// Best-effort removal of a file's contents before deleting it.
/// </summary>
/// <remarks>
/// Overwriting defeats undelete tools and helps on hard disks. It can't
/// guarantee that no copy survives: SSDs and phone storage write changes to
/// fresh cells, copy-on-write file systems (APFS, f2fs) keep old blocks,
/// and snapshots, backups, cloud sync and thumbnails hold copies of their
/// own. No app can reach those; full-disk encryption (BitLocker, FileVault,
/// the phone's built-in encryption) is what keeps them unreadable.
/// </remarks>
public static class SecureFile
{
    private const int BufferSize = 1 << 16;

    /// <summary>
    /// Renames the file to a random name (so its name doesn't linger in the
    /// folder), overwrites its contents with random bytes, flushes them to the
    /// disk and deletes it. Read-only files are refused.
    /// </summary>
    /// <remarks>
    /// The rename comes first because it needs the same permission as the
    /// delete (to change the folder). Where the system lets the app write the
    /// file but not delete it (iOS grants access to a picked file, not its
    /// folder), the file is left as it was instead of overwritten and kept.
    /// </remarks>
    /// <exception cref="FileNotFoundException">The file doesn't exist.</exception>
    /// <exception cref="UnauthorizedAccessException">
    /// The file is read-only, or the system doesn't allow changing it or its folder. The file is left as it was.
    /// </exception>
    public static void OverwriteAndDelete(string path)
    {
        var info = new FileInfo(path);
        if (!info.Exists)
        {
            throw new FileNotFoundException("The file doesn't exist.", path);
        }
        if (info.IsReadOnly)
        {
            throw new UnauthorizedAccessException("The file is read-only.");
        }

        string scrambled = Path.Combine(info.DirectoryName!, "." + Guid.NewGuid().ToString("N"));
        File.Move(path, scrambled);
        try
        {
            using var stream = new FileStream(scrambled, FileMode.Open, FileAccess.Write, FileShare.None, BufferSize,
                FileOptions.WriteThrough);
            Overwrite(stream, stream.Length);
            stream.Flush(flushToDisk: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            File.Move(scrambled, path); // couldn't open it to overwrite: put it back untouched
            throw;
        }
        File.Delete(scrambled);
    }

    /// <summary>Writes <paramref name="length"/> random bytes at the stream's current position.</summary>
    public static void Overwrite(Stream stream, long length)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentOutOfRangeException.ThrowIfNegative(length);

        byte[] buffer = new byte[BufferSize];
        for (long written = 0; written < length;)
        {
            int count = (int)Math.Min(buffer.Length, length - written);
            RandomNumberGenerator.Fill(buffer.AsSpan(0, count));
            stream.Write(buffer, 0, count);
            written += count;
        }
        stream.Flush();
    }
}
