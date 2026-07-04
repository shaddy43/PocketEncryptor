using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace PocketEncryptor
{
    public class Program
    {
        // Crypto parameters
        private const int SaltSize = 16;   // PBKDF2 salt
        private const int NonceSize = 12;  // AES-GCM standard 96-bit nonce
        private const int TagSize = 16;    // AES-GCM 128-bit authentication tag
        private const int KeySize = 32;    // AES-256
        private const int Pbkdf2Iterations = 600_000; // OWASP (2023) PBKDF2-HMAC-SHA256 guidance

        // File format header
        private static readonly byte[] Magic = Encoding.ASCII.GetBytes("PKEC");
        private const byte FormatVersion = 0x01;
        private static readonly int HeaderSize = Magic.Length + 1 + SaltSize + NonceSize + TagSize; // 49 bytes

        static int Main(string[] args)
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

            if (mode.Equals("-E"))
            {
                return RunEncrypt(inputPath, outputPath);
            }
            else if (mode.Equals("-D"))
            {
                return RunDecrypt(inputPath, outputPath);
            }
            else if (mode.Equals("-r"))
            {
                return RunEncryptRecursive(inputPath, outputPath);
            }
            else
            {
                Console.WriteLine("No valid process.... Please write either -E for encryption, -D for decryption, or -r for recursive directory encryption");
                PrintUsage();
                return 1;
            }
        }

        static void PrintUsage()
        {
            Console.WriteLine("Usage: PocketEncryptor <input> <output> <-E|-D|-r>");
            Console.WriteLine("  -E  Encrypt input_file to output_file (you will be prompted for a passphrase)");
            Console.WriteLine("  -D  Decrypt input_file to output_file (you will be prompted for the passphrase)");
            Console.WriteLine("  -r  Recursively encrypt every file under input_dir, writing encrypted");
            Console.WriteLine("      copies (.pkec) into output_dir with the same passphrase for all files");
            Console.WriteLine("Eg: PocketEncryptor secret.docx secret.enc -E");
            Console.WriteLine("    PocketEncryptor ./my_folder ./encrypted_folder -r");
        }

        static int RunEncrypt(string inputPath, string outputPath)
        {
            try
            {
                string password = ReadNewPasswordWithConfirmation();
                if (password == null)
                {
                    Console.WriteLine("Aborted: passphrases did not match.");
                    return 1;
                }

                Console.WriteLine("Encrypting your file, please wait...");
                byte[] plain = File.ReadAllBytes(inputPath);
                byte[] output = Encrypt(plain, password);
                File.WriteAllBytes(outputPath, output);
                Console.WriteLine("Encrypted !!! File saved in: " + outputPath);
                return 0;
            }
            catch (Exception ex)
            {
                return ReportError(ex, inputPath, outputPath);
            }
        }

        static int RunDecrypt(string inputPath, string outputPath)
        {
            try
            {
                string password = ReadPassword("Enter passphrase: ");

                Console.WriteLine("Decrypting your file, please wait...");
                byte[] fileBytes = File.ReadAllBytes(inputPath);
                // Decrypt fully into memory first so a failure never leaves a
                // corrupt/partial output file on disk.
                byte[] plain = Decrypt(fileBytes, password);
                File.WriteAllBytes(outputPath, plain);
                Console.WriteLine("Decrypted !!! File saved in: " + outputPath);
                return 0;
            }
            catch (Exception ex)
            {
                return ReportError(ex, inputPath, outputPath);
            }
        }

        // Encrypted files produced by -r get this extra extension so they are
        // easy to spot and so re-running -r into the same tree skips them.
        private const string EncryptedExtension = ".pkec";

        static int RunEncryptRecursive(string inputDir, string outputDir)
        {
            if (!Directory.Exists(inputDir))
            {
                Console.WriteLine("File error: directory not found: " + inputDir);
                return 1;
            }

            string password = ReadNewPasswordWithConfirmation();
            if (password == null)
            {
                Console.WriteLine("Aborted: passphrases did not match.");
                return 1;
            }

            // Resolve to full paths so we can reliably skip the output directory
            // if it happens to live inside the input directory (which would
            // otherwise make us try to re-encrypt our own output).
            string inputRoot = Path.GetFullPath(inputDir);
            string outputRoot = Path.GetFullPath(outputDir);

            Console.WriteLine("Encrypting all files under: " + inputRoot);
            int succeeded = 0;
            int failed = 0;
            EncryptDirectoryRecursive(inputRoot, inputRoot, outputRoot, password, ref succeeded, ref failed);

            Console.WriteLine("Done. " + succeeded + " file(s) encrypted, " + failed + " failed.");
            return failed == 0 ? 0 : 1;
        }

        // Walks currentDir, encrypting each file into outputRoot while preserving
        // the tree's relative structure, then recurses into each subdirectory.
        public static void EncryptDirectoryRecursive(string inputRoot, string currentDir, string outputRoot,
            string password, ref int succeeded, ref int failed)
        {
            foreach (string file in Directory.GetFiles(currentDir))
            {
                try
                {
                    string relative = Path.GetRelativePath(inputRoot, file);
                    string destPath = Path.Combine(outputRoot, relative + EncryptedExtension);
                    Directory.CreateDirectory(Path.GetDirectoryName(destPath));

                    byte[] plain = File.ReadAllBytes(file);
                    byte[] encrypted = Encrypt(plain, password);
                    File.WriteAllBytes(destPath, encrypted);

                    Console.WriteLine("Encrypted: " + relative);
                    succeeded++;
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Failed:    " + file + " (" + ex.Message + ")");
                    failed++;
                }
            }

            foreach (string subDir in Directory.GetDirectories(currentDir))
            {
                // Don't descend into the output directory if it is nested inside
                // the input tree, otherwise we'd encrypt our own output.
                if (Path.GetFullPath(subDir).Equals(outputRoot, StringComparison.Ordinal))
                {
                    continue;
                }
                EncryptDirectoryRecursive(inputRoot, subDir, outputRoot, password, ref succeeded, ref failed);
            }
        }

        static int ReportError(Exception ex, string inputPath, string outputPath)
        {
            switch (ex)
            {
                case CryptographicException _:
                    // AES-GCM tag mismatch: wrong password or tampered/corrupt file.
                    Console.WriteLine("Decryption failed: wrong passphrase or the file is corrupted/tampered with.");
                    break;
                case InvalidDataException _:
                    // Header validation messages are already user-facing.
                    Console.WriteLine(ex.Message);
                    break;
                case FileNotFoundException _:
                case DirectoryNotFoundException _:
                case UnauthorizedAccessException _:
                case IOException _:
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

        // Derives a 256-bit AES key from a passphrase using PBKDF2-HMAC-SHA256.
        static byte[] DeriveKey(string password, byte[] salt, int iterations = Pbkdf2Iterations)
        {
            using (var kdf = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256))
            {
                return kdf.GetBytes(KeySize);
            }
        }

        // Encrypts plaintext with AES-256-GCM and returns a self-describing byte
        // array: [magic][version][salt][nonce][tag][ciphertext].
        public static byte[] Encrypt(byte[] plaintext, string password)
        {
            byte[] salt = new byte[SaltSize];
            byte[] nonce = new byte[NonceSize];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
                rng.GetBytes(nonce);
            }

            byte[] key = DeriveKey(password, salt);
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[TagSize];

            using (var aes = new AesGcm(key))
            {
                aes.Encrypt(nonce, plaintext, ciphertext, tag);
            }

            byte[] output = new byte[HeaderSize + ciphertext.Length];
            int offset = 0;
            Buffer.BlockCopy(Magic, 0, output, offset, Magic.Length); offset += Magic.Length;
            output[offset] = FormatVersion; offset += 1;
            Buffer.BlockCopy(salt, 0, output, offset, SaltSize); offset += SaltSize;
            Buffer.BlockCopy(nonce, 0, output, offset, NonceSize); offset += NonceSize;
            Buffer.BlockCopy(tag, 0, output, offset, TagSize); offset += TagSize;
            Buffer.BlockCopy(ciphertext, 0, output, offset, ciphertext.Length);

            return output;
        }

        // Parses and verifies a file produced by Encrypt, returning the plaintext.
        // Throws InvalidDataException for a malformed header and
        // CryptographicException for a wrong passphrase or tampered content.
        public static byte[] Decrypt(byte[] fileBytes, string password)
        {
            if (fileBytes.Length < HeaderSize)
            {
                throw new InvalidDataException("This does not look like a valid PocketEncryptor file (too short).");
            }

            int offset = 0;
            for (int i = 0; i < Magic.Length; i++)
            {
                if (fileBytes[i] != Magic[i])
                {
                    throw new InvalidDataException("This does not look like a valid PocketEncryptor file (bad or missing header).");
                }
            }
            offset += Magic.Length;

            byte version = fileBytes[offset]; offset += 1;
            if (version != FormatVersion)
            {
                throw new InvalidDataException("Unsupported file format version: " + version + ".");
            }

            byte[] salt = new byte[SaltSize];
            Buffer.BlockCopy(fileBytes, offset, salt, 0, SaltSize); offset += SaltSize;

            byte[] nonce = new byte[NonceSize];
            Buffer.BlockCopy(fileBytes, offset, nonce, 0, NonceSize); offset += NonceSize;

            byte[] tag = new byte[TagSize];
            Buffer.BlockCopy(fileBytes, offset, tag, 0, TagSize); offset += TagSize;

            int cipherLength = fileBytes.Length - HeaderSize;
            byte[] ciphertext = new byte[cipherLength];
            Buffer.BlockCopy(fileBytes, offset, ciphertext, 0, cipherLength);

            byte[] key = DeriveKey(password, salt);
            byte[] plaintext = new byte[cipherLength];

            using (var aes = new AesGcm(key))
            {
                aes.Decrypt(nonce, ciphertext, tag, plaintext);
            }

            return plaintext;
        }

        // Reads a passphrase from the console without echoing the real characters.
        static string ReadPassword(string prompt)
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

            // Note: .NET strings are immutable and interned, so the passphrase
            // cannot be reliably zeroed from memory. Acceptable for a personal tool.
            return sb.ToString();
        }

        // Prompts for a passphrase twice (encrypt path) to catch typos. Returns
        // null after 3 mismatched attempts.
        static string ReadNewPasswordWithConfirmation()
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
}
