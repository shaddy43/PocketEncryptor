using PocketEncryptor.Core;

namespace PocketEncryptor.App.Services;

/// <summary>
/// The user's own file behind a picked file, for "Purge" (delete originals
/// after encrypting). Only sources the app is allowed to delete have one.
/// </summary>
internal interface IOriginalFile
{
    /// <summary>Null if the app can delete the original, otherwise why not.</summary>
    string? WhyNotRemovable { get; }

    /// <summary>Overwrites the original's contents (best effort) and deletes it.</summary>
    Task RemoveAsync();
}

/// <summary>An original with a real path (Windows; macOS later).</summary>
internal sealed class PathOriginal(string path) : IOriginalFile
{
    public string FullPath { get; } = Path.GetFullPath(path);

    public string? WhyNotRemovable =>
        !File.Exists(FullPath) ? "it no longer exists"
        : new FileInfo(FullPath).IsReadOnly ? "it's read-only"
        : null;

    public Task RemoveAsync() => Task.Run(() => SecureFile.OverwriteAndDelete(FullPath));
}

/// <summary>A file to load into the app, plus its original if the app may delete it.</summary>
internal sealed record PickedFile(FileResult File, IOriginalFile? Original)
{
    /// <summary>A file on disk that the user picked or dropped: its original is the file itself.</summary>
    public static PickedFile FromPath(string path) => new(new FileResult(path), new PathOriginal(path));
}
