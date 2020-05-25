using System;
using System.Data;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Encryption
{
    internal class Program
    {
        private static readonly byte[] buffer = new byte[short.MaxValue];
        private static readonly int byteSize = ushort.MaxValue;
        private static readonly byte[] salt = new byte[byteSize];
        private static readonly int Iterations = 70000;
        private static int Read = 0;

        private static void Main()
        {
            Console.Write("Password: ");
            string password = Console.ReadLine();

            Console.Write("Do you wanna encrypt or decrypt?\n1: Encrypt \n2: Decrypt\nInput: ");
            string input = Console.ReadLine();

            Console.Write("Inputfile: ");
            string inputfile = Console.ReadLine();

            if (input == "1")
                EncryptFile(inputfile, password);
            else if (input == "2")
            {
                Console.Write("Outputfile: ");
                DecryptFile(inputfile, Console.ReadLine(), password);
            }

            password = null;
            Console.WriteLine("Password: " + password);

            Console.ReadLine();
        }

        private static void EncryptFile(string inputFile, string password)
        {
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
                for (int i = 0; i < 10; i++)
                    rng.GetBytes(salt);

            Rfc2898DeriveBytes mykey = new Rfc2898DeriveBytes(Encoding.UTF8.GetBytes(password), salt, Iterations);

            using (Aes aes = Aes.Create())
            using (FileStream fsIn = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
            using (FileStream fsCrypt = new FileStream(inputFile + ".encrypted", FileMode.Create))
            {
                AddParametersToAes(aes, mykey);
                fsCrypt.Write(salt, 0, salt.Length);

                using (CryptoStream crypto = new CryptoStream(fsCrypt, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    while ((Read = fsIn.Read(buffer, 0, buffer.Length)) > 0)
                        crypto.Write(buffer, 0, Read);
            }
        }

        private static void DecryptFile(string inputFile, string outputFile, string password)
        {
            using FileStream fsCrypt = new FileStream(inputFile, FileMode.Open);
            fsCrypt.Read(salt, 0, salt.Length);

            string Driveletter = outputFile[0..(outputFile.IndexOf(@"\") + 1)];
            var OSDrive = DriveInfo.GetDrives().Where(x => x.IsReady && x.Name.Equals(Driveletter, StringComparison.OrdinalIgnoreCase)).FirstOrDefault();
            
            if (OSDrive.AvailableFreeSpace < fsCrypt.Length * 1.5)
            {
                fsCrypt.Close();
                Console.WriteLine("Not enough space to do this operation!");

                Console.ReadLine();
                Environment.Exit(0);
            }

            Rfc2898DeriveBytes mykey = new Rfc2898DeriveBytes(Encoding.UTF8.GetBytes(password), salt, Iterations);
            using (Aes aes = Aes.Create())
            {
                AddParametersToAes(aes, mykey);

                using (CryptoStream crypto = new CryptoStream(fsCrypt, aes.CreateDecryptor(), CryptoStreamMode.Read))
                using (FileStream fsOut = new FileStream(outputFile, FileMode.Create))
                {
                    while ((Read = crypto.Read(buffer, 0, buffer.Length)) > 0)
                        fsOut.Write(buffer, 0, Read);
                }
            }
        }

        private static void AddParametersToAes(Aes aes, Rfc2898DeriveBytes mykey)
        {
            aes.KeySize = 256;
            aes.BlockSize = 128;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = mykey.GetBytes(aes.KeySize / 8);
            aes.IV = mykey.GetBytes(aes.BlockSize / 8);
            aes.Mode = CipherMode.CBC;
        }
    }
}
