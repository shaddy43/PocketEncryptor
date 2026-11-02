namespace PocketEncryptor.Core;

/// <summary>
/// Names and saves output files without ever replacing an existing file.
/// </summary>
public static class OutputFiles
{
    private static readonly string[] EncryptedExtensions = [PkecFormat.FileExtension, ".enc"];

    /// <summary>"photo.jpg" → "photo.jpg.pkec".</summary>
    public static string ForEncrypted(string fileName) => fileName + PkecFormat.FileExtension;

    /// <summary>"photo.jpg.pkec" → "photo.jpg"; any other name gets ".decrypted" appended.</summary>
    public static string ForDecrypted(string fileName)
    {
        foreach (string extension in EncryptedExtensions)
        {
            if (fileName.Length > extension.Length && fileName.EndsWith(extension, StringComparison.OrdinalIgnoreCase))
            {
                return fileName[..^extension.Length];
            }
        }
        return fileName + ".decrypted";
    }

    /// <summary>"photo.jpg", 2 → "photo (2).jpg"; "photo.jpg.pkec", 2 → "photo (2).jpg.pkec".</summary>
    public static string WithCounter(string fileName, int counter)
    {
        // Keep ".pkec" last, so a numbered encrypted file still decrypts to a
        // usable name: "photo (2).jpg.pkec" → "photo (2).jpg", not "photo.jpg (2)".
        string pkec = PkecFormat.FileExtension;
        if (fileName.Length > pkec.Length && fileName.EndsWith(pkec, StringComparison.OrdinalIgnoreCase))
        {
            return WithCounter(fileName[..^pkec.Length], counter) + fileName[^pkec.Length..];
        }

        string extension = Path.GetExtension(fileName);
        string stem = fileName[..^extension.Length];
        return stem.Length == 0
            ? $"{fileName} ({counter})" // ".bashrc" → ".bashrc (1)"
            : $"{stem} ({counter}){extension}";
    }

    /// <summary>
    /// Copies <paramref name="sourcePath"/> into <paramref name="folder"/> as
    /// <paramref name="fileName"/>, or "name (1).ext", "name (2).ext", … if that
    /// name is taken. Never replaces an existing file, and never leaves a
    /// half-written file under the final name.
    /// </summary>
    /// <returns>The full path of the new file.</returns>
    public static string CopyIntoFolder(string sourcePath, string folder, string fileName)
    {
        if (string.IsNullOrWhiteSpace(fileName) || Path.GetFileName(fileName) != fileName)
        {
            throw new ArgumentException("Must be a plain file name, not a path.", nameof(fileName));
        }

        string staging = Path.Combine(folder, "." + fileName + "." + Guid.NewGuid().ToString("N")[..8] + ".tmp");
        try
        {
            File.Copy(sourcePath, staging);
            for (int counter = 0; ; counter++)
            {
                string candidate = Path.Combine(folder, counter == 0 ? fileName : WithCounter(fileName, counter));
                try
                {
                    File.Move(staging, candidate, overwrite: false);
                    return candidate;
                }
                catch (IOException) when (counter < 10_000 && (File.Exists(candidate) || Directory.Exists(candidate)))
                {
                    // Name taken; try the next one.
                }
            }
        }
        finally
        {
            try
            {
                File.Delete(staging); // no-op once moved
            }
            catch (IOException)
            {
                // Best effort.
            }
        }
    }
}
