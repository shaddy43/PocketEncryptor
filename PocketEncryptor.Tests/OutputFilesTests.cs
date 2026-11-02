using PocketEncryptor.Core;
using static PocketEncryptor.Tests.TestHelpers;

namespace PocketEncryptor.Tests;

public sealed class OutputFilesTests : IDisposable
{
    private readonly string _root = NewTempDir();

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    [Theory]
    [InlineData("photo.jpg", "photo.jpg.pkec")]
    [InlineData("README", "README.pkec")]
    public void ForEncrypted_AppendsExtension(string name, string expected) =>
        Assert.Equal(expected, OutputFiles.ForEncrypted(name));

    [Theory]
    [InlineData("photo.jpg.pkec", "photo.jpg")]
    [InlineData("photo.jpg.PKEC", "photo.jpg")]
    [InlineData("notes.txt.enc", "notes.txt")]
    [InlineData("archive", "archive.decrypted")]
    [InlineData(".pkec", ".pkec.decrypted")]
    public void ForDecrypted_StripsKnownExtension(string name, string expected) =>
        Assert.Equal(expected, OutputFiles.ForDecrypted(name));

    [Theory]
    [InlineData("photo.jpg", 1, "photo (1).jpg")]
    [InlineData("photo.jpg.pkec", 1, "photo (1).jpg.pkec")]
    [InlineData("photo.jpg.PKEC", 3, "photo (3).jpg.PKEC")]
    [InlineData("README.pkec", 1, "README (1).pkec")]
    [InlineData("README", 2, "README (2)")]
    [InlineData(".bashrc", 1, ".bashrc (1)")]
    [InlineData(".pkec", 1, ".pkec (1)")]
    public void WithCounter_InsertsBeforeTheRealExtension(string name, int counter, string expected) =>
        Assert.Equal(expected, OutputFiles.WithCounter(name, counter));

    [Fact]
    public void NumberedEncryptedName_DecryptsToUsableName() =>
        Assert.Equal("photo (1).jpg", OutputFiles.ForDecrypted(OutputFiles.WithCounter("photo.jpg.pkec", 1)));

    [Fact]
    public void CopyIntoFolder_NeverReplacesExistingFiles()
    {
        string source = Path.Combine(_root, "source.bin");
        File.WriteAllBytes(source, [1, 2, 3]);
        string folder = Directory.CreateDirectory(Path.Combine(_root, "out")).FullName;
        File.WriteAllBytes(Path.Combine(folder, "a.txt"), [9]);
        File.WriteAllBytes(Path.Combine(folder, "a (1).txt"), [8]);

        string first = OutputFiles.CopyIntoFolder(source, folder, "a.txt");
        string second = OutputFiles.CopyIntoFolder(source, folder, "a.txt");

        Assert.Equal(Path.Combine(folder, "a (2).txt"), first);
        Assert.Equal(Path.Combine(folder, "a (3).txt"), second);
        Assert.Equal([9], File.ReadAllBytes(Path.Combine(folder, "a.txt")));
        Assert.Equal([8], File.ReadAllBytes(Path.Combine(folder, "a (1).txt")));
        Assert.Equal([1, 2, 3], File.ReadAllBytes(first));
        Assert.Equal(4, Directory.GetFiles(folder).Length); // no staging files left
    }

    [Fact]
    public void CopyIntoFolder_UsesNameAsIsWhenFree()
    {
        string source = Path.Combine(_root, "source.bin");
        File.WriteAllBytes(source, [1]);

        string saved = OutputFiles.CopyIntoFolder(source, _root, "new.pkec");

        Assert.Equal(Path.Combine(_root, "new.pkec"), saved);
    }

    [Theory]
    [InlineData("../escape.txt")]
    [InlineData("sub/file.txt")]
    [InlineData("")]
    public void CopyIntoFolder_RejectsPaths(string name)
    {
        string source = Path.Combine(_root, "source.bin");
        File.WriteAllBytes(source, [1]);

        Assert.Throws<ArgumentException>(() => OutputFiles.CopyIntoFolder(source, _root, name));
    }
}
