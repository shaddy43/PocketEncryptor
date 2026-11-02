using System.Security.Cryptography;
using PocketEncryptor.Core;

namespace PocketEncryptor.Tests;

internal static class TestHelpers
{
    /// <summary>Cheap key derivation and tiny chunks so multi-chunk cases run fast.</summary>
    public static readonly EncryptionOptions Fast = new() { Iterations = 1_000, ChunkSize = 16 };

    public const int V2HeaderSize = PkecFormat.V2HeaderSize;
    public const int SealedChunk = 16 + PkecFormat.TagSize; // for Fast.ChunkSize

    public static byte[] RandomBytes(int length) => RandomNumberGenerator.GetBytes(length);

    public static string NewTempDir()
    {
        string dir = Path.Combine(Path.GetTempPath(), "pkec_test_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }
}
