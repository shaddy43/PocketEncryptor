using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace PocketEncryptor.Core;

/// <summary>
/// Password-based file encryption: PBKDF2-HMAC-SHA256 key derivation and
/// chunked AES-256-GCM. See <see cref="PkecFormat"/> for the file layout.
/// </summary>
/// <remarks>
/// <para>Errors:</para>
/// <list type="bullet">
/// <item><see cref="CryptographicException"/>: wrong password, or the data was
/// tampered with or corrupted.</item>
/// <item><see cref="InvalidDataException"/>: not a PocketEncryptor file, truncated,
/// or an unsupported version. The message is safe to show to the user.</item>
/// <item><see cref="PlatformNotSupportedException"/>: AES-GCM isn't available on
/// this OS (check <see cref="IsSupported"/>).</item>
/// </list>
/// <para>
/// Every method here is synchronous and CPU-bound: key derivation alone takes
/// roughly 0.2–1 s. UI code should call it through <c>Task.Run</c>.
/// </para>
/// </remarks>
public static class PocketCrypto
{
    // v2 header field offsets.
    private const int IterationsOffset = PkecFormat.PreambleSize;               // 5
    private const int ChunkSizeOffset = IterationsOffset + 4;                   // 9
    private const int SaltOffset = ChunkSizeOffset + 4;                         // 13
    private const int NoncePrefixOffset = SaltOffset + PkecFormat.SaltSize;     // 29

    /// <summary>True when this platform provides AES-GCM.</summary>
    public static bool IsSupported => AesGcm.IsSupported;

    // ------------------------------------------------------------------
    // Byte-array convenience API (whole file in memory)
    // ------------------------------------------------------------------

    public static byte[] Encrypt(byte[] plaintext, string password, EncryptionOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        using var input = new MemoryStream(plaintext, writable: false);
        using var output = new MemoryStream();
        Encrypt(input, output, password, options);
        return output.ToArray();
    }

    public static byte[] Decrypt(byte[] fileBytes, string password)
    {
        ArgumentNullException.ThrowIfNull(fileBytes);
        using var input = new MemoryStream(fileBytes, writable: false);
        using var output = new MemoryStream();
        Decrypt(input, output, password);
        return output.ToArray();
    }

    // ------------------------------------------------------------------
    // File API: streams through the file and writes the result atomically
    // ------------------------------------------------------------------

    /// <summary>
    /// Encrypts <paramref name="inputPath"/> into <paramref name="outputPath"/>.
    /// The output is written to a temporary file and moved into place only on
    /// success, so a failure never leaves a partial file behind, and input and
    /// output may be the same path.
    /// </summary>
    public static void EncryptFile(string inputPath, string outputPath, string password,
        EncryptionOptions? options = null, IProgress<long>? progress = null,
        CancellationToken cancellationToken = default)
    {
        WriteAtomically(outputPath, output =>
        {
            using var input = OpenRead(inputPath);
            Encrypt(input, output, password, options, progress, cancellationToken);
        });
    }

    /// <summary>
    /// Decrypts <paramref name="inputPath"/> into <paramref name="outputPath"/>.
    /// Nothing is written to <paramref name="outputPath"/> unless the whole file
    /// authenticates.
    /// </summary>
    public static void DecryptFile(string inputPath, string outputPath, string password,
        IProgress<long>? progress = null, CancellationToken cancellationToken = default)
    {
        WriteAtomically(outputPath, output =>
        {
            using var input = OpenRead(inputPath);
            Decrypt(input, output, password, progress, cancellationToken);
        });
    }

    // ------------------------------------------------------------------
    // Stream API: constant memory, works with any Stream (e.g. ones from
    // a mobile document picker)
    // ------------------------------------------------------------------

    /// <summary>
    /// Encrypts all of <paramref name="input"/> into <paramref name="output"/>
    /// using the current (v2) format.
    /// </summary>
    /// <param name="progress">Receives the total plaintext bytes processed so far.</param>
    public static void Encrypt(Stream input, Stream output, string password,
        EncryptionOptions? options = null, IProgress<long>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(password);
        options ??= EncryptionOptions.Default;
        options.Validate();
        EnsureSupported();
        cancellationToken.ThrowIfCancellationRequested();

        int chunkSize = options.ChunkSize;
        byte[] header = new byte[PkecFormat.V2HeaderSize];
        PkecFormat.Magic.CopyTo(header);
        header[PkecFormat.PreambleSize - 1] = PkecFormat.Version2;
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(IterationsOffset, 4), (uint)options.Iterations);
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(ChunkSizeOffset, 4), (uint)chunkSize);
        RandomNumberGenerator.Fill(header.AsSpan(SaltOffset, PkecFormat.SaltSize));
        RandomNumberGenerator.Fill(header.AsSpan(NoncePrefixOffset, PkecFormat.NoncePrefixSize));

        byte[] key = DeriveKeyV2(password, header.AsSpan(SaltOffset, PkecFormat.SaltSize), options.Iterations);
        byte[] current = SecretBuffer(chunkSize); // plaintext
        byte[] next = SecretBuffer(chunkSize);
        byte[] sealedChunk = new byte[chunkSize + PkecFormat.TagSize];
        try
        {
            output.Write(header);

            using var aes = new AesGcm(key, PkecFormat.TagSize);
            Span<byte> nonce = stackalloc byte[PkecFormat.NonceSize];
            ReadOnlySpan<byte> noncePrefix = header.AsSpan(NoncePrefixOffset, PkecFormat.NoncePrefixSize);

            int currentLength = ReadFull(input, current);
            uint counter = 0;
            long processed = 0;
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();

                // Read ahead one chunk to learn whether the current one is the last.
                int nextLength = currentLength == chunkSize ? ReadFull(input, next) : 0;
                bool isLast = nextLength == 0;

                BuildChunkNonce(nonce, noncePrefix, counter, isLast);
                aes.Encrypt(nonce,
                    current.AsSpan(0, currentLength),
                    sealedChunk.AsSpan(0, currentLength),
                    sealedChunk.AsSpan(currentLength, PkecFormat.TagSize),
                    header);
                output.Write(sealedChunk, 0, currentLength + PkecFormat.TagSize);

                processed += currentLength;
                progress?.Report(processed);

                if (isLast)
                {
                    break;
                }
                counter = NextCounter(counter);
                (current, next) = (next, current);
                currentLength = nextLength;
            }
            output.Flush();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(current);
            CryptographicOperations.ZeroMemory(next);
        }
    }

    /// <summary>
    /// Decrypts a v1 or v2 file from <paramref name="input"/> into
    /// <paramref name="output"/>.
    /// </summary>
    /// <remarks>
    /// Each chunk is authenticated before it's written, but truncation is only
    /// detected at the end. If this throws, discard everything already written
    /// to <paramref name="output"/>. <see cref="DecryptFile"/> does that for you.
    /// </remarks>
    /// <param name="progress">Receives the total plaintext bytes written so far.</param>
    public static void Decrypt(Stream input, Stream output, string password,
        IProgress<long>? progress = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(password);
        EnsureSupported();

        byte[] preamble = new byte[PkecFormat.PreambleSize];
        if (ReadFull(input, preamble) < preamble.Length)
        {
            throw TooShort();
        }
        if (!preamble.AsSpan(0, PkecFormat.Magic.Length).SequenceEqual(PkecFormat.Magic))
        {
            throw new InvalidDataException("This does not look like a valid PocketEncryptor file (bad or missing header).");
        }

        byte version = preamble[PkecFormat.PreambleSize - 1];
        switch (version)
        {
            case PkecFormat.Version2:
                DecryptV2(preamble, input, output, password, progress, cancellationToken);
                break;
            case PkecFormat.Version1:
                DecryptV1(preamble, input, output, password, progress, cancellationToken);
                break;
            default:
                throw new InvalidDataException("Unsupported file format version: " + version + ".");
        }
        output.Flush();
    }

    // ------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------

    private static void DecryptV2(byte[] preamble, Stream input, Stream output, string password,
        IProgress<long>? progress, CancellationToken cancellationToken)
    {
        byte[] header = new byte[PkecFormat.V2HeaderSize];
        preamble.CopyTo(header, 0);
        int rest = PkecFormat.V2HeaderSize - PkecFormat.PreambleSize;
        if (ReadFull(input, header.AsSpan(PkecFormat.PreambleSize)) < rest)
        {
            throw TooShort();
        }

        uint iterations = BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(IterationsOffset, 4));
        uint chunkSizeRaw = BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(ChunkSizeOffset, 4));
        if (iterations < 1 || iterations > PkecFormat.MaxIterations ||
            chunkSizeRaw < 1 || chunkSizeRaw > PkecFormat.MaxChunkSize)
        {
            throw new InvalidDataException("This PocketEncryptor file has an invalid header (it may be damaged).");
        }
        int chunkSize = (int)chunkSizeRaw;
        int sealedSize = chunkSize + PkecFormat.TagSize;

        byte[] key = DeriveKeyV2(password, header.AsSpan(SaltOffset, PkecFormat.SaltSize), (int)iterations);
        byte[] current = new byte[sealedSize];
        byte[] next = new byte[sealedSize];
        byte[] plain = SecretBuffer(chunkSize);
        try
        {
            using var aes = new AesGcm(key, PkecFormat.TagSize);
            Span<byte> nonce = stackalloc byte[PkecFormat.NonceSize];
            ReadOnlySpan<byte> noncePrefix = header.AsSpan(NoncePrefixOffset, PkecFormat.NoncePrefixSize);

            int currentLength = ReadFull(input, current);
            uint counter = 0;
            long processed = 0;
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();

                if (currentLength < PkecFormat.TagSize)
                {
                    throw new InvalidDataException("This PocketEncryptor file is incomplete (it was truncated).");
                }

                int nextLength = currentLength == sealedSize ? ReadFull(input, next) : 0;
                bool isLast = nextLength == 0;
                int plainLength = currentLength - PkecFormat.TagSize;

                BuildChunkNonce(nonce, noncePrefix, counter, isLast);
                aes.Decrypt(nonce,
                    current.AsSpan(0, plainLength),
                    current.AsSpan(plainLength, PkecFormat.TagSize),
                    plain.AsSpan(0, plainLength),
                    header);
                output.Write(plain, 0, plainLength);

                processed += plainLength;
                progress?.Report(processed);

                if (isLast)
                {
                    break;
                }
                counter = NextCounter(counter);
                (current, next) = (next, current);
                currentLength = nextLength;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    // Legacy single-shot format. It has one tag over the whole file, so it
    // can't be streamed: buffer it all, as the original tool did.
    private static void DecryptV1(byte[] preamble, Stream input, Stream output, string password,
        IProgress<long>? progress, CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream();
        buffer.Write(preamble);
        input.CopyTo(buffer);
        cancellationToken.ThrowIfCancellationRequested();

        ReadOnlySpan<byte> file = buffer.GetBuffer().AsSpan(0, (int)buffer.Length);
        if (file.Length < PkecFormat.V1HeaderSize)
        {
            throw TooShort();
        }

        int offset = PkecFormat.PreambleSize;
        ReadOnlySpan<byte> salt = file.Slice(offset, PkecFormat.SaltSize); offset += PkecFormat.SaltSize;
        ReadOnlySpan<byte> nonce = file.Slice(offset, PkecFormat.NonceSize); offset += PkecFormat.NonceSize;
        ReadOnlySpan<byte> tag = file.Slice(offset, PkecFormat.TagSize); offset += PkecFormat.TagSize;
        ReadOnlySpan<byte> ciphertext = file[offset..];

        // v1 hashed the password exactly as typed (no Unicode normalization).
        byte[] key = DeriveKey(password, salt, PkecFormat.V1Iterations);
        byte[] plain = SecretBuffer(ciphertext.Length);
        try
        {
            using (var aes = new AesGcm(key, PkecFormat.TagSize))
            {
                aes.Decrypt(nonce, ciphertext, tag, plain);
            }
            output.Write(plain);
            progress?.Report(plain.Length);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    // Normalizes to NFC first: the "same" password typed on different
    // keyboards/OSes (e.g. "é" as one code point vs "e" + combining accent)
    // must produce the same key.
    private static byte[] DeriveKeyV2(string password, ReadOnlySpan<byte> salt, int iterations) =>
        DeriveKey(password.Normalize(NormalizationForm.FormC), salt, iterations);

    private static byte[] DeriveKey(string password, ReadOnlySpan<byte> salt, int iterations)
    {
        byte[] passwordBytes = SecretBuffer(Encoding.UTF8.GetByteCount(password));
        byte[] key = SecretBuffer(PkecFormat.KeySize);
        try
        {
            Encoding.UTF8.GetBytes(password, passwordBytes);
            Rfc2898DeriveBytes.Pbkdf2(passwordBytes, salt, key, iterations, HashAlgorithmName.SHA256);
            return key;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(key);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }

    // Keys, password bytes and plaintext go in pinned arrays: the garbage
    // collector never moves pinned memory, so it never leaves stray copies,
    // and zeroing the array afterwards really erases it. (The password string
    // itself can't be wiped; strings are immutable in .NET.)
    private static byte[] SecretBuffer(int length) => GC.AllocateArray<byte>(length, pinned: true);

    private static void BuildChunkNonce(Span<byte> nonce, ReadOnlySpan<byte> prefix, uint counter, bool isLast)
    {
        prefix.CopyTo(nonce);
        BinaryPrimitives.WriteUInt32BigEndian(nonce.Slice(PkecFormat.NoncePrefixSize, 4), counter);
        nonce[PkecFormat.NonceSize - 1] = isLast ? (byte)1 : (byte)0;
    }

    private static uint NextCounter(uint counter)
    {
        if (counter == uint.MaxValue)
        {
            throw new IOException("File is too large for the configured chunk size.");
        }
        return counter + 1;
    }

    // Stream.Read may return fewer bytes than asked for; keep reading until the
    // buffer is full or the stream ends.
    private static int ReadFull(Stream stream, Span<byte> buffer)
    {
        int total = 0;
        while (total < buffer.Length)
        {
            int read = stream.Read(buffer[total..]);
            if (read == 0)
            {
                break;
            }
            total += read;
        }
        return total;
    }

    private static FileStream OpenRead(string path) =>
        new(path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, FileOptions.SequentialScan);

    private static void WriteAtomically(string outputPath, Action<Stream> write)
    {
        ArgumentNullException.ThrowIfNull(outputPath);
        string fullPath = Path.GetFullPath(outputPath);
        string directory = Path.GetDirectoryName(fullPath)!;
        string tempPath = Path.Combine(directory,
            "." + Path.GetFileName(fullPath) + "." + Guid.NewGuid().ToString("N")[..8] + ".tmp");

        try
        {
            using (var output = new FileStream(tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920))
            {
                write(output);
                output.Flush(flushToDisk: true);
            }
            File.Move(tempPath, fullPath, overwrite: true);
        }
        catch
        {
            try { File.Delete(tempPath); } catch { /* best effort */ }
            throw;
        }
    }

    private static void EnsureSupported()
    {
        if (!AesGcm.IsSupported)
        {
            throw new PlatformNotSupportedException("AES-GCM is not available on this platform.");
        }
    }

    private static InvalidDataException TooShort() =>
        new("This does not look like a valid PocketEncryptor file (too short).");
}
