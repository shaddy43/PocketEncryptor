namespace PocketEncryptor.Core;

/// <summary>Outcome for a single file during directory encryption.</summary>
/// <param name="SourcePath">Full path of the original file.</param>
/// <param name="RelativePath">Path relative to the input root.</param>
/// <param name="OutputPath">Full path of the encrypted copy (where it was or would have been written).</param>
/// <param name="Error">Why this file failed, or null on success.</param>
public sealed record DirectoryFileResult(string SourcePath, string RelativePath, string OutputPath, Exception? Error)
{
    public bool Succeeded => Error is null;
}

public sealed record DirectoryEncryptionSummary(int Succeeded, int Failed);

/// <summary>
/// Encrypts every file under a directory tree into a mirrored output tree,
/// adding <see cref="PkecFormat.FileExtension"/> to each name. Originals are
/// never modified.
/// </summary>
public static class DirectoryEncryptor
{
    // Windows and (by default) macOS have case-insensitive file systems.
    private static readonly StringComparison PathComparison =
        OperatingSystem.IsLinux() || OperatingSystem.IsAndroid() ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase;

    /// <param name="onFile">Called after each file, whether it succeeded or failed.</param>
    /// <remarks>
    /// One file failing doesn't stop the run; it's counted and reported via
    /// <paramref name="onFile"/>. Cancellation stops the run with
    /// <see cref="OperationCanceledException"/>.
    /// </remarks>
    public static DirectoryEncryptionSummary EncryptDirectory(string inputDir, string outputDir, string password,
        EncryptionOptions? options = null, Action<DirectoryFileResult>? onFile = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(inputDir);
        ArgumentNullException.ThrowIfNull(outputDir);
        ArgumentNullException.ThrowIfNull(password);

        string inputRoot = Path.GetFullPath(inputDir);
        string outputRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(outputDir));
        if (!Directory.Exists(inputRoot))
        {
            throw new DirectoryNotFoundException("Directory not found: " + inputDir);
        }

        int succeeded = 0;
        int failed = 0;
        Walk(inputRoot);
        return new DirectoryEncryptionSummary(succeeded, failed);

        void Walk(string currentDir)
        {
            foreach (string file in Directory.GetFiles(currentDir))
            {
                cancellationToken.ThrowIfCancellationRequested();

                string relative = Path.GetRelativePath(inputRoot, file);
                string destPath = Path.Combine(outputRoot, relative + PkecFormat.FileExtension);
                Exception? error = null;
                try
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(destPath)!);
                    PocketCrypto.EncryptFile(file, destPath, password, options, cancellationToken: cancellationToken);
                    succeeded++;
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    error = ex;
                    failed++;
                }
                onFile?.Invoke(new DirectoryFileResult(file, relative, destPath, error));
            }

            foreach (string subDir in Directory.GetDirectories(currentDir))
            {
                // If the output directory is nested inside the input tree, don't
                // descend into it, or we'd encrypt our own output.
                if (string.Equals(Path.TrimEndingDirectorySeparator(Path.GetFullPath(subDir)), outputRoot, PathComparison))
                {
                    continue;
                }
                Walk(subDir);
            }
        }
    }
}
