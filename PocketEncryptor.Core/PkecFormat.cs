namespace PocketEncryptor.Core;

/// <summary>
/// Constants describing the on-disk .pkec file format.
/// </summary>
/// <remarks>
/// <para><b>Version 2</b> (written by this library) — chunked, streamable:</para>
/// <code>
/// [4]  magic "PKEC"
/// [1]  version 0x02
/// [4]  PBKDF2 iterations   (uint32, big-endian)
/// [4]  chunk size in bytes (uint32, big-endian)
/// [16] PBKDF2 salt
/// [7]  random nonce prefix
/// then one or more chunks, each: [ciphertext (≤ chunk size)][16-byte GCM tag]
/// </code>
/// <para>
/// Chunk <c>i</c> uses nonce = prefix(7) ‖ i (uint32 BE) ‖ final-flag(1), and the
/// whole 36-byte header as associated data. Every chunk except the last holds
/// exactly <c>chunk size</c> plaintext bytes; the last has the final flag set.
/// That makes reordering, dropping, truncating or appending chunks, and any change
/// to the header, fail authentication.
/// </para>
/// <para><b>Version 1</b> (legacy, decrypt-only) — single-shot AES-GCM:</para>
/// <code>
/// [4] magic "PKEC" [1] 0x01 [16] salt [12] nonce [16] tag [N] ciphertext
/// </code>
/// </remarks>
public static class PkecFormat
{
    public static ReadOnlySpan<byte> Magic => "PKEC"u8;

    public const byte Version1 = 0x01;
    public const byte Version2 = 0x02;
    public const byte CurrentVersion = Version2;

    public const int SaltSize = 16;
    public const int TagSize = 16;
    public const int KeySize = 32;          // AES-256
    public const int NonceSize = 12;        // AES-GCM standard 96-bit nonce
    public const int NoncePrefixSize = 7;   // v2: 7 random + 4 counter + 1 flag

    /// <summary>Bytes before the version-specific part: magic + version.</summary>
    public const int PreambleSize = 5;

    /// <summary>Full v2 header: magic, version, iterations, chunk size, salt, nonce prefix.</summary>
    public const int V2HeaderSize = PreambleSize + 4 + 4 + SaltSize + NoncePrefixSize; // 36

    /// <summary>Full v1 header: magic, version, salt, nonce, tag.</summary>
    public const int V1HeaderSize = PreambleSize + SaltSize + NonceSize + TagSize; // 49

    /// <summary>
    /// Upper bounds accepted when reading a header, so a crafted file can't make
    /// us spin for hours on key derivation or allocate huge buffers.
    /// </summary>
    public const int MaxIterations = 10_000_000;

    /// <summary>v1 files didn't record their iteration count; it was always this.</summary>
    public const int V1Iterations = 600_000;
    public const int MaxChunkSize = 16 * 1024 * 1024;

    /// <summary>Extension used for files produced by directory encryption.</summary>
    public const string FileExtension = ".pkec";

    /// <summary>
    /// True if <paramref name="fileStart"/> (the first bytes of a file) begins with
    /// the PocketEncryptor magic. A quick check, not a validity guarantee.
    /// </summary>
    public static bool HasMagic(ReadOnlySpan<byte> fileStart) => fileStart.StartsWith(Magic);
}
