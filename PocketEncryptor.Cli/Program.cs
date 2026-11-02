using System.Security.Cryptography;
using System.Text;
using PocketEncryptor.Core;

namespace PocketEncryptor.Cli;

public static class Program
{
    public static int Main(string[] args)
    {
        Console.WriteLine("This is your personal pocket encryptor");

        if (args.Length != 3)
        {
            PrintUsage();
            return 1;
        }

        string inputPath = args[0];
        string outputPath = args[1];
        string mode = args[2];

        switch (mode)
        {
            case "-E":
                return RunEncrypt(inputPath, outputPath);
            case "-D":
                return RunDecrypt(inputPath, outputPath);
            case "-r":
                return RunEncryptRecursive(inputPath, outputPath);
            default:
                Console.WriteLine("No valid process.... Please write either -E for encryption, -D for decryption, or -r for recursive directory encryption");
                PrintUsage();
                return 1;
        }
    }

    private static void PrintUsage()
    {
        Console.WriteLine("Usage: PocketEncryptor <input> <output> <-E|-D|-r>");
        Console.WriteLine("  -E  Encrypt input_file to output_file (you will be prompted for a passphrase)");
        Console.WriteLine("  -D  Decrypt input_file to output_file (you will be prompted for the passphrase)");
        Console.WriteLine("  -r  Recursively encrypt every file under input_dir, writing encrypted");
        Console.WriteLine("      copies (.pkec) into output_dir with the same passphrase for all files");
        Console.WriteLine("Eg: PocketEncryptor secret.docx secret.enc -E");
        Console.WriteLine("    PocketEncryptor ./my_folder ./encrypted_folder -r");
    }

    private static int RunEncrypt(string inputPath, string outputPath)
    {
        try
        {
            string? password = ReadNewPasswordWithConfirmation();
            if (password == null)
            {
                Console.WriteLine("Aborted: passphrases did not match.");
                return 1;
            }

            Console.WriteLine("Encrypting your file, please wait...");
            PocketCrypto.EncryptFile(inputPath, outputPath, password);
            Console.WriteLine("Encrypted !!! File saved in: " + outputPath);
            return 0;
        }
        catch (Exception ex)
        {
            return ReportError(ex);
        }
    }

    private static int RunDecrypt(string inputPath, string outputPath)
    {
        try
        {
            string password = ReadPassword("Enter passphrase: ");

            Console.WriteLine("Decrypting your file, please wait...");
            // DecryptFile only writes outputPath once the whole file has
            // authenticated, so a failure never leaves a corrupt/partial file.
            PocketCrypto.DecryptFile(inputPath, outputPath, password);
            Console.WriteLine("Decrypted !!! File saved in: " + outputPath);
            return 0;
        }
        catch (Exception ex)
        {
            return ReportError(ex);
        }
    }

    private static int RunEncryptRecursive(string inputDir, string outputDir)
    {
        if (!Directory.Exists(inputDir))
        {
            Console.WriteLine("File error: directory not found: " + inputDir);
            return 1;
        }

        string? password = ReadNewPasswordWithConfirmation();
        if (password == null)
        {
            Console.WriteLine("Aborted: passphrases did not match.");
            return 1;
        }

        try
        {
            Console.WriteLine("Encrypting all files under: " + Path.GetFullPath(inputDir));
            DirectoryEncryptionSummary summary = DirectoryEncryptor.EncryptDirectory(
                inputDir, outputDir, password,
                onFile: result => Console.WriteLine(result.Succeeded
                    ? "Encrypted: " + result.RelativePath
                    : "Failed:    " + result.SourcePath + " (" + result.Error!.Message + ")"));

            Console.WriteLine("Done. " + summary.Succeeded + " file(s) encrypted, " + summary.Failed + " failed.");
            return summary.Failed == 0 ? 0 : 1;
        }
        catch (Exception ex)
        {
            return ReportError(ex);
        }
    }

    private static int ReportError(Exception ex)
    {
        switch (ex)
        {
            case CryptographicException:
                // AES-GCM tag mismatch: wrong password or tampered/corrupt file.
                Console.WriteLine("Decryption failed: wrong passphrase or the file is corrupted/tampered with.");
                break;
            case InvalidDataException:
                // Header validation messages are already user-facing.
                Console.WriteLine(ex.Message);
                break;
            case PlatformNotSupportedException:
                Console.WriteLine("Not supported: " + ex.Message);
                break;
            case UnauthorizedAccessException:
            case IOException:
                Console.WriteLine("File error: " + ex.Message);
                break;
            default:
                Console.WriteLine("Unexpected error: " + ex.Message);
                break;
        }

        // Debugging escape hatch: full details only when explicitly requested.
        if (Environment.GetEnvironmentVariable("POCKETENCRYPTOR_DEBUG") == "1")
        {
            Console.WriteLine(ex.ToString());
        }

        return 1;
    }

    // Reads a passphrase from the console without echoing the real characters.
    private static string ReadPassword(string prompt)
    {
        Console.Write(prompt);
        var sb = new StringBuilder();
        while (true)
        {
            ConsoleKeyInfo keyInfo = Console.ReadKey(intercept: true);
            if (keyInfo.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                break;
            }
            else if (keyInfo.Key == ConsoleKey.Backspace)
            {
                if (sb.Length > 0)
                {
                    sb.Remove(sb.Length - 1, 1);
                    Console.Write("\b \b");
                }
            }
            else if (!char.IsControl(keyInfo.KeyChar))
            {
                sb.Append(keyInfo.KeyChar);
                Console.Write("*");
            }
        }

        // Note: .NET strings are immutable, so the passphrase can't be reliably
        // zeroed from memory. Acceptable for a personal tool.
        return sb.ToString();
    }

    // Prompts for a passphrase twice (encrypt path) to catch typos. Returns
    // null after 3 mismatched attempts.
    private static string? ReadNewPasswordWithConfirmation()
    {
        for (int attempt = 0; attempt < 3; attempt++)
        {
            string first = ReadPassword("Enter passphrase: ");
            string second = ReadPassword("Confirm passphrase: ");
            if (first == second)
            {
                return first;
            }
            Console.WriteLine("Passphrases do not match. Please try again.");
        }
        return null;
    }
}
