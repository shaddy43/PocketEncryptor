using System.Security.Cryptography;
using System.Text;
using PocketEncryptor.Core;
using static PocketEncryptor.Tests.TestHelpers;

namespace PocketEncryptor.Tests;

public sealed class FileAndDirectoryTests : IDisposable
{
    private readonly string _root = NewTempDir();

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private string P(params string[] parts) => Path.Combine([_root, .. parts]);

    [Fact]
    public void EncryptFile_DecryptFile_RoundTrip()
    {
        byte[] original = RandomBytes(150_000);
        File.WriteAllBytes(P("plain.bin"), original);

        PocketCrypto.EncryptFile(P("plain.bin"), P("plain.bin.pkec"), "pw", Fast);
        PocketCrypto.DecryptFile(P("plain.bin.pkec"), P("restored.bin"), "pw");

        Assert.Equal(original, File.ReadAllBytes(P("restored.bin")));
    }

    [Fact]
    public void DecryptFile_WrongPassword_LeavesNoOutputOrTempFiles()
    {
        File.WriteAllBytes(P("plain.bin"), RandomBytes(1000));
        PocketCrypto.EncryptFile(P("plain.bin"), P("enc.pkec"), "right", Fast);

        Assert.ThrowsAny<CryptographicException>(
            () => PocketCrypto.DecryptFile(P("enc.pkec"), P("out.bin"), "wrong"));

        Assert.False(File.Exists(P("out.bin")));
        Assert.Equal(2, Directory.GetFiles(_root).Length); // just plain.bin + enc.pkec
    }

    [Fact]
    public void VerifyFile_AcceptsAGoodFileAndWritesNothing()
    {
        File.WriteAllBytes(P("plain.bin"), RandomBytes(1000));
        PocketCrypto.EncryptFile(P("plain.bin"), P("enc.pkec"), "pw", Fast);

        PocketCrypto.VerifyFile(P("enc.pkec"), "pw");

        Assert.Equal(2, Directory.GetFiles(_root).Length); // just plain.bin + enc.pkec
    }

    [Fact]
    public void VerifyFile_WrongPasswordOrDamagedFile_Throws()
    {
        File.WriteAllBytes(P("plain.bin"), RandomBytes(1000));
        PocketCrypto.EncryptFile(P("plain.bin"), P("enc.pkec"), "pw", Fast);

        Assert.ThrowsAny<CryptographicException>(() => PocketCrypto.VerifyFile(P("enc.pkec"), "wrong"));

        byte[] enc = File.ReadAllBytes(P("enc.pkec"));
        enc[^1] ^= 1;
        File.WriteAllBytes(P("enc.pkec"), enc);
        Assert.ThrowsAny<CryptographicException>(() => PocketCrypto.VerifyFile(P("enc.pkec"), "pw"));

        File.WriteAllBytes(P("enc.pkec"), enc[..^SealedChunk]);
        Assert.ThrowsAny<CryptographicException>(() => PocketCrypto.VerifyFile(P("enc.pkec"), "pw"));
    }

    [Fact]
    public void DecryptFile_Truncated_KeepsExistingOutputUntouched()
    {
        File.WriteAllBytes(P("plain.bin"), RandomBytes(1000));
        PocketCrypto.EncryptFile(P("plain.bin"), P("enc.pkec"), "pw", Fast);
        byte[] enc = File.ReadAllBytes(P("enc.pkec"));
        File.WriteAllBytes(P("enc.pkec"), enc[..^SealedChunk]);
        File.WriteAllText(P("out.bin"), "previous contents");

        Assert.ThrowsAny<CryptographicException>(
            () => PocketCrypto.DecryptFile(P("enc.pkec"), P("out.bin"), "pw"));

        Assert.Equal("previous contents", File.ReadAllText(P("out.bin")));
    }

    [Fact]
    public void EncryptFile_InPlace_Works()
    {
        byte[] original = RandomBytes(500);
        File.WriteAllBytes(P("doc.txt"), original);

        PocketCrypto.EncryptFile(P("doc.txt"), P("doc.txt"), "pw", Fast);
        Assert.NotEqual(original, File.ReadAllBytes(P("doc.txt")));

        PocketCrypto.DecryptFile(P("doc.txt"), P("doc.txt"), "pw");
        Assert.Equal(original, File.ReadAllBytes(P("doc.txt")));
    }

    [Fact]
    public void EncryptFile_MissingInput_ThrowsFileNotFound()
    {
        Assert.Throws<FileNotFoundException>(
            () => PocketCrypto.EncryptFile(P("nope.txt"), P("out.pkec"), "pw", Fast));
        Assert.Empty(Directory.GetFiles(_root));
    }

    [Fact]
    public void EncryptDirectory_EncryptsAllFilesPreservingStructure()
    {
        string inputDir = P("in");
        string outputDir = P("out");
        Directory.CreateDirectory(Path.Combine(inputDir, "sub"));
        byte[] c1 = Encoding.UTF8.GetBytes("file one contents");
        byte[] c2 = RandomBytes(1000);
        File.WriteAllBytes(Path.Combine(inputDir, "a.txt"), c1);
        File.WriteAllBytes(Path.Combine(inputDir, "sub", "b.bin"), c2);

        var results = new List<DirectoryFileResult>();
        DirectoryEncryptionSummary summary =
            DirectoryEncryptor.EncryptDirectory(inputDir, outputDir, "dir-password", Fast, results.Add);

        Assert.Equal(new DirectoryEncryptionSummary(2, 0), summary);
        Assert.Equal(2, results.Count);
        Assert.All(results, r => Assert.True(r.Succeeded));

        // Structure is mirrored with a .pkec extension...
        string e1 = Path.Combine(outputDir, "a.txt.pkec");
        string e2 = Path.Combine(outputDir, "sub", "b.bin.pkec");
        // ...and every file round-trips with the shared password.
        Assert.Equal(c1, PocketCrypto.Decrypt(File.ReadAllBytes(e1), "dir-password"));
        Assert.Equal(c2, PocketCrypto.Decrypt(File.ReadAllBytes(e2), "dir-password"));
    }

    [Fact]
    public void EncryptDirectory_OutputNestedInInput_IsNotReEncrypted()
    {
        string inputDir = P("in");
        string outputDir = Path.Combine(inputDir, "encrypted");
        Directory.CreateDirectory(outputDir);
        File.WriteAllText(Path.Combine(inputDir, "a.txt"), "a");
        File.WriteAllText(Path.Combine(outputDir, "old.txt.pkec"), "already here");

        DirectoryEncryptionSummary summary =
            DirectoryEncryptor.EncryptDirectory(inputDir, outputDir, "pw", Fast);

        Assert.Equal(new DirectoryEncryptionSummary(1, 0), summary);
        Assert.False(File.Exists(Path.Combine(outputDir, "encrypted", "old.txt.pkec.pkec")));
    }

    [Fact]
    public void EncryptDirectory_MissingInput_ThrowsDirectoryNotFound()
    {
        Assert.Throws<DirectoryNotFoundException>(
            () => DirectoryEncryptor.EncryptDirectory(P("missing"), P("out"), "pw", Fast));
    }
}
