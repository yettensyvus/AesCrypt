using System;
using System.Security.Cryptography;
using System.Text;

namespace AesCrypt
{
    class AesCrypt
    {
        public static string IV;
        public static string Key;

        static void Main(string[] args)
        {

            Console.WriteLine("\n Generate AES Encryption 256 bit Key and IV >> \n\n");

            GenerateKeyIV();

            Console.WriteLine("\n IV = {0}", IV);
            Console.WriteLine("\n Key = {0}", Key);

            string text = Encrypt("Hello World!");

            Console.WriteLine("\n Encrypted Text: {0}", text);
            Console.WriteLine("\n Decrypted Text: {0}", Decrypt(text));

            Console.ReadKey();
        }

        public static void GenerateKeyIV()
        {
            using (Aes aes = Aes.Create())
            {
                aes.KeySize = 256;
                aes.GenerateKey();

                IV = Convert.ToBase64String(aes.IV);
                Key = Convert.ToBase64String(aes.Key);
            }
        }

        public static string Encrypt(string text)
        {
            text = Convert.ToBase64String(Encoding.UTF8.GetBytes(text));

            byte[] textbytes = Convert.FromBase64String(text);
            AesCryptoServiceProvider aesprovider = new AesCryptoServiceProvider();
            aesprovider.BlockSize = 128;
            aesprovider.KeySize = 256;
            aesprovider.Key = Convert.FromBase64String(Key);
            aesprovider.IV = Convert.FromBase64String(IV);
            aesprovider.Padding = PaddingMode.PKCS7;
            aesprovider.Mode = CipherMode.CBC;

            ICryptoTransform icrypt = aesprovider.CreateEncryptor(aesprovider.Key, aesprovider.IV);
            byte[] encryptedData = icrypt.TransformFinalBlock(textbytes, 0, textbytes.Length);
            icrypt.Dispose();

            return Convert.ToBase64String(encryptedData);

        }

        public static string Decrypt(string text)
        {
            byte[] textbytes = Convert.FromBase64String(text);
            AesCryptoServiceProvider aesprovider = new AesCryptoServiceProvider();
            aesprovider.BlockSize = 128;
            aesprovider.KeySize = 256;
            aesprovider.Key = Convert.FromBase64String(Key);
            aesprovider.IV = Convert.FromBase64String(IV);
            aesprovider.Padding = PaddingMode.PKCS7;
            aesprovider.Mode = CipherMode.CBC;

            ICryptoTransform icrypt = aesprovider.CreateDecryptor(aesprovider.Key, aesprovider.IV);
            byte[] dencryptedData = icrypt.TransformFinalBlock(textbytes, 0, textbytes.Length);
            icrypt.Dispose();

            return ASCIIEncoding.ASCII.GetString(dencryptedData);
        }
    }
}