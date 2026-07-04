using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace PocketEncryptor.Tests
{
    public class CryptoTests
    {
        private static byte[] RandomBytes(int length)
        {
            byte[] data = new byte[length];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(data);
            }
            return data;
        }

        [Fact]
        public void RoundTrip_EncryptThenDecrypt_ReturnsOriginalBytes()
        {
            byte[] original = RandomBytes(4096);
            const string password = "correct horse battery staple";

            byte[] encrypted = Program.Encrypt(original, password);
            byte[] decrypted = Program.Decrypt(encrypted, password);

            Assert.Equal(original, decrypted);
        }

        [Fact]
        public void Encrypt_SamePlaintextAndPassword_ProducesDifferentCiphertext()
        {
            byte[] original = Encoding.UTF8.GetBytes("repeatable plaintext");
            const string password = "pw";

            byte[] first = Program.Encrypt(original, password);
            byte[] second = Program.Encrypt(original, password);

            // Random salt + nonce mean the outputs must differ.
            Assert.NotEqual(first, second);
        }

        [Fact]
        public void Decrypt_WrongPassword_ThrowsCryptographicException()
        {
            byte[] original = RandomBytes(256);
            byte[] encrypted = Program.Encrypt(original, "right-password");

            Assert.Throws<CryptographicException>(
                () => Program.Decrypt(encrypted, "wrong-password"));
        }

        [Fact]
        public void Decrypt_TamperedCiphertext_ThrowsCryptographicException()
        {
            byte[] original = RandomBytes(256);
            const string password = "pw";
            byte[] encrypted = Program.Encrypt(original, password);

            // Flip a bit in the ciphertext region (past the 49-byte header).
            encrypted[encrypted.Length - 1] ^= 0xFF;

            Assert.Throws<CryptographicException>(
                () => Program.Decrypt(encrypted, password));
        }

        [Fact]
        public void Decrypt_TruncatedFile_ThrowsInvalidDataException()
        {
            byte[] tooShort = new byte[10];

            Assert.Throws<InvalidDataException>(
                () => Program.Decrypt(tooShort, "pw"));
        }

        [Fact]
        public void Decrypt_BadMagic_ThrowsInvalidDataException()
        {
            byte[] original = RandomBytes(64);
            byte[] encrypted = Program.Encrypt(original, "pw");

            // Corrupt the magic bytes.
            encrypted[0] ^= 0xFF;

            Assert.Throws<InvalidDataException>(
                () => Program.Decrypt(encrypted, "pw"));
        }

        [Fact]
        public void EncryptDirectoryRecursive_EncryptsAllFilesPreservingStructure()
        {
            string root = Path.Combine(Path.GetTempPath(), "pkec_test_" + Guid.NewGuid().ToString("N"));
            string inputDir = Path.Combine(root, "in");
            string outputDir = Path.Combine(root, "out");
            const string password = "dir-password";

            try
            {
                Directory.CreateDirectory(Path.Combine(inputDir, "sub"));
                byte[] c1 = Encoding.UTF8.GetBytes("file one contents");
                byte[] c2 = RandomBytes(1000);
                File.WriteAllBytes(Path.Combine(inputDir, "a.txt"), c1);
                File.WriteAllBytes(Path.Combine(inputDir, "sub", "b.bin"), c2);

                int ok = 0, failed = 0;
                string fullInput = Path.GetFullPath(inputDir);
                Program.EncryptDirectoryRecursive(fullInput, fullInput, Path.GetFullPath(outputDir),
                    password, ref ok, ref failed);

                Assert.Equal(2, ok);
                Assert.Equal(0, failed);

                // Structure is mirrored with a .pkec extension...
                string e1 = Path.Combine(outputDir, "a.txt.pkec");
                string e2 = Path.Combine(outputDir, "sub", "b.bin.pkec");
                Assert.True(File.Exists(e1));
                Assert.True(File.Exists(e2));

                // ...and every file round-trips with the shared password.
                Assert.Equal(c1, Program.Decrypt(File.ReadAllBytes(e1), password));
                Assert.Equal(c2, Program.Decrypt(File.ReadAllBytes(e2), password));
            }
            finally
            {
                if (Directory.Exists(root))
                {
                    Directory.Delete(root, true);
                }
            }
        }
    }
}
