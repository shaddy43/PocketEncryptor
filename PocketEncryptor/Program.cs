using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace PocketEncryptor
{
    internal class Program
    {
        static string aes_key = "";
        static byte[] aes_iv = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

        static void Main(string[] args)
        {
            Console.WriteLine("This is your personal pocket encryptor");

            string file_path = "";
            string output_file = "";
            string process = "";

            if (args.Length == 4)
            {
                file_path = args[0];
                output_file = args[1];
                string input_key = args[2];
                process = args[3];
                aes_key = input_key;

                string hashed = ComputeSha256Hash(aes_key);
                string fixed_hash = hashed.Substring(0, 32);
                aes_key = fixed_hash;

                if (process.Equals("-E"))
                {
                    try
                    {
                        Console.WriteLine("Encrypting your file, please wait...");
                        byte[] plain_file = File.ReadAllBytes(file_path);
                        byte[] byte_encrypted = EncryptAES(Convert.ToBase64String(plain_file));
                        File.WriteAllBytes(output_file, byte_encrypted);
                        Console.WriteLine("Encrypted !!! File saved in: "+output_file);

                        /*byte[] encrypted_file = File.ReadAllBytes(file_path);
                        String byte_string_decrypted = DecryptAES(encrypted_file);
                        byte[] byte_decrypted = Convert.FromBase64String(byte_string_decrypted);
                        File.WriteAllBytes(output_file, byte_decrypted);*/
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("Encryption Failed....!!!");
                        //Console.WriteLine(e);
                    }
                }
                else if (process.Equals("-D"))
                {
                    try
                    {
                        /*byte[] plain_file = File.ReadAllBytes(file_path);
                        byte[] byte_encrypted = EncryptAES(Convert.ToBase64String(plain_file));
                        File.WriteAllBytes(output_file, byte_encrypted);*/

                        Console.WriteLine("Decrypting your file, please wait...");
                        byte[] encrypted_file = File.ReadAllBytes(file_path);
                        String byte_string_decrypted = DecryptAES(encrypted_file);
                        byte[] byte_decrypted = Convert.FromBase64String(byte_string_decrypted);
                        File.WriteAllBytes(output_file, byte_decrypted);
                        Console.WriteLine("Decrypted !!! File saved in: " + output_file);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("Decryption Failed....!!!");
                        //Console.WriteLine(e);
                    }
                }
                else
                {
                    Console.WriteLine("No valid process.... Please write either -E for encryption or -D for decryption");
                }
            }
            else
            {
                Console.WriteLine("Arguements missing!!! \n[1] file path. [2] output file path [3] encryption key [4] process '-E/-D' \nEg: program.exe input_file output_file mysecretkey -E");
            }
        }

        static string ComputeSha256Hash(string rawData)
        {
            // Create a SHA256   
            using (SHA256 sha256Hash = SHA256.Create())
            {
                // ComputeHash - returns byte array  
                byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(rawData));

                // Convert byte array to a string   
                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < bytes.Length; i++)
                {
                    builder.Append(bytes[i].ToString("x2"));
                }
                return builder.ToString();
            }
        }

        public static byte[] EncryptAES(string plainText)
        {
            byte[] encrypted;

            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                aes.Key = Convert.FromBase64String(aes_key);
                aes.IV = aes_iv;

                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                ICryptoTransform enc = aes.CreateEncryptor(aes.Key, aes.IV);

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, enc, CryptoStreamMode.Write))
                    {
                        using (StreamWriter sw = new StreamWriter(cs))
                        {
                            sw.Write(plainText);
                        }

                        encrypted = ms.ToArray();
                    }
                }
            }

            return encrypted;
        }

        public static string DecryptAES(byte[] encrypted)
        {
            string decrypted = null;
            byte[] cipher = encrypted;

            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                aes.Key = Convert.FromBase64String(aes_key);
                //aes.Key = aes_keyy;

                //aes.IV = Convert.FromBase64String(aes_iv);
                aes.IV = aes_iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                ICryptoTransform dec = aes.CreateDecryptor(aes.Key, aes.IV);

                using (MemoryStream ms = new MemoryStream(cipher))
                {
                    using (CryptoStream cs = new CryptoStream(ms, dec, CryptoStreamMode.Read))
                    {
                        using (StreamReader sr = new StreamReader(cs))
                        {
                            decrypted = sr.ReadToEnd();
                        }
                    }
                }
            }
            return decrypted;
        }
    }
}
