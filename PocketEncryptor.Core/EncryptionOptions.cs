namespace PocketEncryptor.Core;

/// <summary>
/// Tunable parameters for encryption. Both values are written into the file
/// header, so decryption never needs them supplied.
/// </summary>
public sealed record EncryptionOptions
{
    /// <summary>OWASP (2023) guidance for PBKDF2-HMAC-SHA256.</summary>
    public const int DefaultIterations = 600_000;

    /// <summary>Plaintext bytes per authenticated chunk.</summary>
    public const int DefaultChunkSize = 64 * 1024;

    public static EncryptionOptions Default { get; } = new();

    public int Iterations { get; init; } = DefaultIterations;

    public int ChunkSize { get; init; } = DefaultChunkSize;

    internal void Validate()
    {
        if (Iterations < 1 || Iterations > PkecFormat.MaxIterations)
        {
            throw new ArgumentOutOfRangeException(nameof(Iterations), Iterations,
                $"Iterations must be between 1 and {PkecFormat.MaxIterations}.");
        }
        if (ChunkSize < 1 || ChunkSize > PkecFormat.MaxChunkSize)
        {
            throw new ArgumentOutOfRangeException(nameof(ChunkSize), ChunkSize,
                $"Chunk size must be between 1 and {PkecFormat.MaxChunkSize} bytes.");
        }
    }
}
