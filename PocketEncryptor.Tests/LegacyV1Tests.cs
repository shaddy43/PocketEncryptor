using System.Security.Cryptography;
using System.Text;
using PocketEncryptor.Core;
using static PocketEncryptor.Tests.TestHelpers;

namespace PocketEncryptor.Tests;

/// <summary>
/// Files written by the previous release (format v1) must keep decrypting.
/// </summary>
public class LegacyV1Tests
{
    // An independent copy of the original v1 encryptor, using the same (now
    // obsolete) APIs, so these tests catch any accidental format drift.
#pragma warning disable SYSLIB0041, SYSLIB0053, SYSLIB0060
    private static byte[] EncryptV1(byte[] plaintext, string password)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] key;
        using (var kdf = new Rfc2898DeriveBytes(password, salt, 600_000, HashAlgorithmName.SHA256))
        {
            key = kdf.GetBytes(32);
        }

        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];
        using (var aes = new AesGcm(key))
        {
            aes.Encrypt(nonce, plaintext, ciphertext, tag);
        }

        return [.. Encoding.ASCII.GetBytes("PKEC"), 0x01, .. salt, .. nonce, .. tag, .. ciphertext];
    }
#pragma warning restore SYSLIB0041, SYSLIB0053, SYSLIB0060

    [Fact]
    public void Decrypt_V1File_ReturnsOriginal()
    {
        byte[] original = RandomBytes(5000);
        byte[] v1 = EncryptV1(original, "legacy password");

        Assert.Equal(original, PocketCrypto.Decrypt(v1, "legacy password"));
    }

    [Fact]
    public void Decrypt_V1EmptyFile_ReturnsEmpty()
    {
        byte[] v1 = EncryptV1([], "pw");

        Assert.Empty(PocketCrypto.Decrypt(v1, "pw"));
    }

    [Fact]
    public void Decrypt_V1WrongPassword_ThrowsCryptographicException()
    {
        byte[] v1 = EncryptV1(RandomBytes(100), "right");

        Assert.ThrowsAny<CryptographicException>(() => PocketCrypto.Decrypt(v1, "wrong"));
    }

    [Fact]
    public void Decrypt_V1Tampered_ThrowsCryptographicException()
    {
        byte[] v1 = EncryptV1(RandomBytes(100), "pw");
        v1[^1] ^= 0xFF;

        Assert.ThrowsAny<CryptographicException>(() => PocketCrypto.Decrypt(v1, "pw"));
    }

    [Fact]
    public void Decrypt_V1Truncated_ThrowsInvalidDataException()
    {
        byte[] v1 = EncryptV1(RandomBytes(100), "pw");

        Assert.Throws<InvalidDataException>(() => PocketCrypto.Decrypt(v1[..40], "pw"));
    }
}
