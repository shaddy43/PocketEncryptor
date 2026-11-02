using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using PocketEncryptor.Core;
using static PocketEncryptor.Tests.TestHelpers;

namespace PocketEncryptor.Tests;

public class CryptoTests
{
    [Fact]
    public void RoundTrip_DefaultOptions_ReturnsOriginalBytes()
    {
        byte[] original = RandomBytes(200_000); // several 64 KiB chunks
        const string password = "correct horse battery staple";

        byte[] encrypted = PocketCrypto.Encrypt(original, password);
        byte[] decrypted = PocketCrypto.Decrypt(encrypted, password);

        Assert.Equal(original, decrypted);
    }

    [Fact]
    public void Encrypt_WritesV2HeaderWithDefaultParameters()
    {
        byte[] encrypted = PocketCrypto.Encrypt(new byte[10], "pw");

        Assert.Equal("PKEC"u8.ToArray(), encrypted[..4]);
        Assert.Equal(PkecFormat.Version2, encrypted[4]);
        Assert.Equal((uint)EncryptionOptions.DefaultIterations, BinaryPrimitives.ReadUInt32BigEndian(encrypted.AsSpan(5)));
        Assert.Equal((uint)EncryptionOptions.DefaultChunkSize, BinaryPrimitives.ReadUInt32BigEndian(encrypted.AsSpan(9)));
    }

    // Sizes around chunk boundaries (chunk size 16): empty, partial, exact, exact+1, many.
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(15)]
    [InlineData(16)]
    [InlineData(17)]
    [InlineData(32)]
    [InlineData(1000)]
    public void RoundTrip_ChunkBoundaries(int length)
    {
        byte[] original = RandomBytes(length);

        byte[] encrypted = PocketCrypto.Encrypt(original, "pw", Fast);

        // Exactly ceil(len/16) chunks, or one empty chunk for an empty file.
        int chunks = Math.Max(1, (length + 15) / 16);
        Assert.Equal(V2HeaderSize + length + chunks * PkecFormat.TagSize, encrypted.Length);
        Assert.Equal(original, PocketCrypto.Decrypt(encrypted, "pw"));
    }

    [Fact]
    public void Encrypt_SamePlaintextAndPassword_ProducesDifferentCiphertext()
    {
        byte[] original = Encoding.UTF8.GetBytes("repeatable plaintext");

        byte[] first = PocketCrypto.Encrypt(original, "pw", Fast);
        byte[] second = PocketCrypto.Encrypt(original, "pw", Fast);

        // Random salt + nonce prefix mean the outputs must differ.
        Assert.NotEqual(first, second);
    }

    [Fact]
    public void Decrypt_WrongPassword_ThrowsCryptographicException()
    {
        byte[] encrypted = PocketCrypto.Encrypt(RandomBytes(256), "right-password", Fast);

        Assert.ThrowsAny<CryptographicException>(() => PocketCrypto.Decrypt(encrypted, "wrong-password"));
    }

    [Fact]
    public void Password_IsUnicodeNormalized()
    {
        // "café" with a precomposed é (NFC) vs "e" + combining acute (NFD):
        // different keyboards/OSes can produce either for the same keystrokes.
        string nfc = "café";
        string nfd = "café";
        byte[] original = RandomBytes(64);

        byte[] encrypted = PocketCrypto.Encrypt(original, nfc, Fast);

        Assert.Equal(original, PocketCrypto.Decrypt(encrypted, nfd));
    }

    [Theory]
    [InlineData(V2HeaderSize + 3)]                    // first chunk
    [InlineData(V2HeaderSize + SealedChunk + 5)]      // middle chunk
    [InlineData(-1)]                                  // last byte (final tag)
    public void Decrypt_TamperedCiphertext_ThrowsCryptographicException(int index)
    {
        byte[] encrypted = PocketCrypto.Encrypt(RandomBytes(100), "pw", Fast);
        encrypted[index < 0 ? encrypted.Length + index : index] ^= 0x01;

        Assert.ThrowsAny<CryptographicException>(() => PocketCrypto.Decrypt(encrypted, "pw"));
    }

    [Theory]
    [InlineData(13)] // salt
    [InlineData(29)] // nonce prefix
    [InlineData(35)] // last header byte
    public void Decrypt_TamperedHeader_ThrowsCryptographicException(int index)
    {
        byte[] encrypted = PocketCrypto.Encrypt(RandomBytes(100), "pw", Fast);
        encrypted[index] ^= 0x01;

        Assert.ThrowsAny<CryptographicException>(() => PocketCrypto.Decrypt(encrypted, "pw"));
    }

    [Fact]
    public void Decrypt_ChangedChunkSizeInHeader_Fails()
    {
        byte[] encrypted = PocketCrypto.Encrypt(RandomBytes(100), "pw", Fast);
        BinaryPrimitives.WriteUInt32BigEndian(encrypted.AsSpan(9), 32);

        // The header is authenticated, so this can never yield plaintext.
        Assert.ThrowsAny<CryptographicException>(() => PocketCrypto.Decrypt(encrypted, "pw"));
    }

    [Fact]
    public void Decrypt_TruncatedAtChunkBoundary_ThrowsCryptographicException()
    {
        // 3 full chunks; drop the last one so the file ends cleanly on a boundary.
        byte[] encrypted = PocketCrypto.Encrypt(RandomBytes(48), "pw", Fast);
        byte[] truncated = encrypted[..^SealedChunk];

        // The new "last" chunk was sealed as non-final, so authentication fails.
        Assert.ThrowsAny<CryptographicException>(() => PocketCrypto.Decrypt(truncated, "pw"));
    }

    [Fact]
    public void Decrypt_TruncatedMidChunk_Throws()
    {
        byte[] encrypted = PocketCrypto.Encrypt(RandomBytes(48), "pw", Fast);
        byte[] truncated = encrypted[..^5];

        Assert.ThrowsAny<CryptographicException>(() => PocketCrypto.Decrypt(truncated, "pw"));
    }

    [Fact]
    public void Decrypt_HeaderOnly_ThrowsInvalidDataException()
    {
        byte[] encrypted = PocketCrypto.Encrypt(RandomBytes(48), "pw", Fast);

        Assert.Throws<InvalidDataException>(() => PocketCrypto.Decrypt(encrypted[..V2HeaderSize], "pw"));
    }

    [Fact]
    public void Decrypt_AppendedData_ThrowsCryptographicException()
    {
        byte[] encrypted = PocketCrypto.Encrypt(RandomBytes(48), "pw", Fast);
        byte[] extended = [.. encrypted, .. RandomBytes(SealedChunk)];

        Assert.ThrowsAny<CryptographicException>(() => PocketCrypto.Decrypt(extended, "pw"));
    }

    [Fact]
    public void Decrypt_ReorderedChunks_ThrowsCryptographicException()
    {
        byte[] encrypted = PocketCrypto.Encrypt(RandomBytes(48), "pw", Fast);
        int a = V2HeaderSize, b = V2HeaderSize + SealedChunk;
        byte[] first = encrypted[a..b];
        encrypted.AsSpan(b, SealedChunk).CopyTo(encrypted.AsSpan(a));
        first.CopyTo(encrypted, b);

        Assert.ThrowsAny<CryptographicException>(() => PocketCrypto.Decrypt(encrypted, "pw"));
    }

    [Fact]
    public void HasMagic_DetectsEncryptedFiles()
    {
        Assert.True(PkecFormat.HasMagic(PocketCrypto.Encrypt([1, 2, 3], "pw", Fast)));
        Assert.False(PkecFormat.HasMagic("%PDF-1.7"u8));
        Assert.False(PkecFormat.HasMagic("PK"u8)); // shorter than the magic
        Assert.False(PkecFormat.HasMagic([]));
    }

    [Fact]
    public void Decrypt_TooShort_ThrowsInvalidDataException()
    {
        Assert.Throws<InvalidDataException>(() => PocketCrypto.Decrypt(new byte[3], "pw"));
        Assert.Throws<InvalidDataException>(() => PocketCrypto.Decrypt(new byte[10], "pw"));
    }

    [Fact]
    public void Decrypt_BadMagic_ThrowsInvalidDataException()
    {
        byte[] encrypted = PocketCrypto.Encrypt(RandomBytes(64), "pw", Fast);
        encrypted[0] ^= 0xFF;

        Assert.Throws<InvalidDataException>(() => PocketCrypto.Decrypt(encrypted, "pw"));
    }

    [Fact]
    public void Decrypt_UnknownVersion_ThrowsInvalidDataException()
    {
        byte[] encrypted = PocketCrypto.Encrypt(RandomBytes(64), "pw", Fast);
        encrypted[4] = 0x7F;

        var ex = Assert.Throws<InvalidDataException>(() => PocketCrypto.Decrypt(encrypted, "pw"));
        Assert.Contains("version", ex.Message);
    }

    [Theory]
    [InlineData(5, 0u)]                      // zero iterations
    [InlineData(5, 4_000_000_000u)]          // absurd iterations (would hang)
    [InlineData(9, 0u)]                      // zero chunk size
    [InlineData(9, 1_000_000_000u)]          // absurd chunk size (would allocate GBs)
    public void Decrypt_UnreasonableHeaderParameters_ThrowsInvalidDataException(int offset, uint value)
    {
        byte[] encrypted = PocketCrypto.Encrypt(RandomBytes(64), "pw", Fast);
        BinaryPrimitives.WriteUInt32BigEndian(encrypted.AsSpan(offset), value);

        Assert.Throws<InvalidDataException>(() => PocketCrypto.Decrypt(encrypted, "pw"));
    }

    [Fact]
    public void Encrypt_InvalidOptions_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => PocketCrypto.Encrypt([1], "pw", new EncryptionOptions { ChunkSize = 0 }));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => PocketCrypto.Encrypt([1], "pw", new EncryptionOptions { Iterations = 0 }));
    }

    [Fact]
    public void Stream_ReportsProgressAndHandlesShortReads()
    {
        byte[] original = RandomBytes(1000);
        var reports = new List<long>();
        var progress = new SynchronousProgress(reports.Add);

        using var encrypted = new MemoryStream();
        PocketCrypto.Encrypt(new TrickleStream(original), encrypted, "pw", Fast, progress);

        Assert.Equal(1000, reports[^1]);
        Assert.Equal(reports.OrderBy(x => x), reports);

        using var decrypted = new MemoryStream();
        PocketCrypto.Decrypt(new TrickleStream(encrypted.ToArray()), decrypted, "pw");
        Assert.Equal(original, decrypted.ToArray());
    }

    [Fact]
    public void Stream_Cancellation_Throws()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        Assert.ThrowsAny<OperationCanceledException>(() =>
            PocketCrypto.Encrypt(new MemoryStream(new byte[100]), new MemoryStream(), "pw", Fast,
                cancellationToken: cts.Token));
    }

    /// <summary>IProgress that reports inline (Progress&lt;T&gt; posts asynchronously).</summary>
    private sealed class SynchronousProgress(Action<long> report) : IProgress<long>
    {
        public void Report(long value) => report(value);
    }

    /// <summary>A read-only stream that returns at most 3 bytes per Read, like a slow network or picker stream.</summary>
    private sealed class TrickleStream(byte[] data) : MemoryStream(data, writable: false)
    {
        public override int Read(Span<byte> buffer) => base.Read(buffer[..Math.Min(3, buffer.Length)]);
        public override int Read(byte[] buffer, int offset, int count) => base.Read(buffer, offset, Math.Min(3, count));
    }
}
