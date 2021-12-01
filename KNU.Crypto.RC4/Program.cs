using KNU.Crypto.RC4.Ciphers;
using System;
using System.Text;

namespace KNU.Crypto.RC4
{
    internal class Program
    {
        static void Main(string[] args)
        {
            string plainText = "Text to encrypt.";
            string key = "Secret cipher key.";

            var plainBytes = Encoding.UTF8.GetBytes(plainText);
            var keyBytes = Encoding.UTF8.GetBytes(key);

            var cipher = new Algorithm(keyBytes);

            var encryptedBytes = cipher.Encrypt(plainBytes);
            var decryptedBytes = cipher.Decrypt(encryptedBytes);

            var decryptedText = Encoding.UTF8.GetString(decryptedBytes);

            Console.WriteLine("Phrase:\t\t\t{0}", plainText);
            Console.WriteLine("Phrase Bytes:\t\t{0}", BitConverter.ToString(plainBytes));
            Console.WriteLine("Key Phrase:\t\t{0}", key);
            Console.WriteLine("Key Bytes:\t\t{0}", BitConverter.ToString(keyBytes));
            Console.WriteLine("Encryption Result:\t{0}", BitConverter.ToString(encryptedBytes));
            Console.WriteLine("Decryption Result:\t{0}", BitConverter.ToString(decryptedBytes));
            Console.WriteLine("Decrypted Phrase:\t{0}", decryptedText);

            Console.WriteLine(Environment.NewLine + "Press enter to close");
            Console.ReadLine();
        }
    }
}
