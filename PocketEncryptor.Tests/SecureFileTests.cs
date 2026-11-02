using PocketEncryptor.Core;
using static PocketEncryptor.Tests.TestHelpers;

namespace PocketEncryptor.Tests;

public sealed class SecureFileTests : IDisposable
{
    private readonly string _root = NewTempDir();

    public void Dispose()
    {
        foreach (string file in Directory.GetFiles(_root))
        {
            File.SetAttributes(file, FileAttributes.Normal);
        }
        Directory.Delete(_root, recursive: true);
    }

    [Fact]
    public void OverwriteAndDelete_RemovesTheFileAndLeavesNothingBehind()
    {
        string path = Path.Combine(_root, "secret.txt");
        File.WriteAllBytes(path, RandomBytes(200_000));
        File.WriteAllText(Path.Combine(_root, "other.txt"), "keep me");

        SecureFile.OverwriteAndDelete(path);

        Assert.False(File.Exists(path));
        Assert.Equal(["other.txt"], Directory.GetFiles(_root).Select(Path.GetFileName));
    }

    [Fact]
    public void OverwriteAndDelete_HandlesEmptyFiles()
    {
        string path = Path.Combine(_root, "empty.txt");
        File.WriteAllBytes(path, []);

        SecureFile.OverwriteAndDelete(path);

        Assert.False(File.Exists(path));
    }

    [Fact]
    public void OverwriteAndDelete_RefusesReadOnlyFilesAndKeepsThem()
    {
        string path = Path.Combine(_root, "protected.txt");
        File.WriteAllText(path, "original");
        File.SetAttributes(path, FileAttributes.ReadOnly);

        Assert.Throws<UnauthorizedAccessException>(() => SecureFile.OverwriteAndDelete(path));
        Assert.Equal("original", File.ReadAllText(path));
    }

    [Fact]
    public void OverwriteAndDelete_MissingFileThrows() =>
        Assert.Throws<FileNotFoundException>(() => SecureFile.OverwriteAndDelete(Path.Combine(_root, "nope")));

    [Fact]
    public void Overwrite_ReplacesEveryByteWithoutChangingTheLength()
    {
        byte[] original = new byte[150_000]; // all zeros
        using var stream = new MemoryStream();
        stream.Write(original);
        stream.Position = 0;

        SecureFile.Overwrite(stream, original.Length);

        byte[] after = stream.ToArray();
        Assert.Equal(original.Length, after.Length);
        // Random bytes are zero only ~0.4% of the time; the original was all zeros.
        Assert.True(after.Count(b => b != 0) > after.Length * 0.99);
    }
}
