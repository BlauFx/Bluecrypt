using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Encryption
{
    internal class Program
    {
        private static readonly byte[] buffer = new byte[short.MaxValue], salt = new byte[ushort.MaxValue];
        private static readonly int Iterations = 70000;
        private static int Read;

        private static Aes Aes = Aes.Create();

        private static void Main()
        {
            Console.Write("Password: ");
            string password = GetPassword();

            Console.Write("Confirm password: ");
            string password2 = GetPassword();

            while (!password.Equals(password2))
            {
                Console.WriteLine("Wrong password\nRetry again\nConfirm password: ");
                password2 = GetPassword();
            }

            Console.Clear();

            Console.Write("Do you wanna encrypt or decrypt?\n1: Encrypt \n2: Decrypt\nInput: ");
            string input = Console.ReadLine();

            Console.Write("Inputfile: ");
            string inputfile = Console.ReadLine();

            EnsureFileExist(ref inputfile);

            if (input == "1")
                EncryptFile(inputfile, password);
            else if (input == "2")
            {
                Console.Write("Outputfile: ");
                DecryptFile(inputfile, Console.ReadLine(), password);
            }

            Aes.Clear();

            Console.WriteLine($"Done, operation completed\nAlgorithm: AES\nKeysize: {Aes.Key.Length*8}\nCipherMode: {Aes.Mode}\nPadding: {Aes.Padding}");
            Console.ReadLine();
        }

        private static void EncryptFile(string inputFile, string password)
        {
            CheckIfEnoughStorageIsAvailable(inputFile, inputFile);

            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
                for (int i = 0; i < 10; i++)
                    rng.GetBytes(salt);

            Rfc2898DeriveBytes mykey = GetKey(password);

            using (FileStream fsIn = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
            using (FileStream fsCrypt = new FileStream($"{inputFile}.encrypted", FileMode.Create))
            {
                AddParametersToAes(Aes, mykey);
                fsCrypt.Write(salt, 0, salt.Length);

                using (CryptoStream crypto = new CryptoStream(fsCrypt, Aes.CreateEncryptor(), CryptoStreamMode.Write))
                    while ((Read = fsIn.Read(buffer, 0, buffer.Length)) > 0)
                        crypto.Write(buffer, 0, Read);
            }
        }

        private static void DecryptFile(string inputFile, string outputFile, string password)
        {
            using FileStream fsCrypt = new FileStream(inputFile, FileMode.Open);
            fsCrypt.Read(salt, 0, salt.Length);

            CheckIfEnoughStorageIsAvailable(inputFile, outputFile);

            Rfc2898DeriveBytes mykey = GetKey(password);
            AddParametersToAes(Aes, mykey);

            using (CryptoStream crypto = new CryptoStream(fsCrypt, Aes.CreateDecryptor(), CryptoStreamMode.Read))
            using (FileStream fsOut = new FileStream(outputFile, FileMode.Create))
            {
                while ((Read = crypto.Read(buffer, 0, buffer.Length)) > 0)
                    fsOut.Write(buffer, 0, Read);
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

        private static Rfc2898DeriveBytes GetKey (string password) => new Rfc2898DeriveBytes(Encoding.UTF8.GetBytes(password), salt, Iterations, HashAlgorithmName.SHA256);

        private static void EnsureFileExist(ref string inputfile)
        {
            if (inputfile is null)
                throw new Exception("Operation aborted!\nInputfile can't be null!");

            if (inputfile.StartsWith("\"") || inputfile.StartsWith("\'"))
                inputfile = inputfile[1..];

            if (inputfile.EndsWith("\"") || inputfile.EndsWith("\'"))
                inputfile = inputfile[..^1];

            if (!File.Exists(inputfile))
                throw new FileNotFoundException($"Operation aborted!\nFile does not exist!\nCouldn't find: {inputfile}");
        }

        private static void CheckIfEnoughStorageIsAvailable(string input, string destinationDrive)
        {
            DriveInfo osDrive = new DriveInfo(Path.GetPathRoot(new FileInfo(destinationDrive).FullName) ?? throw new Exception($"{destinationDrive} could not be found"));
            using var fileStrm = new FileStream(input, FileMode.Open);

            if (osDrive.AvailableFreeSpace < fileStrm.Length * 1.5)
            {
                Console.WriteLine("Not enough space available to perform this operation!");
                Console.ReadLine();
                Environment.Exit(0);
            }
        }

        private static string GetPassword()
        {
            string password = "";
            ConsoleKeyInfo info = Console.ReadKey(true);

            while (info.Key != ConsoleKey.Enter)
            {
                if (info.Key != ConsoleKey.Backspace)
                {
                    Console.Write("*");
                    password += info.KeyChar;
                }
                else if (info.Key == ConsoleKey.Backspace)
                {
                    if (!string.IsNullOrEmpty(password))
                    {
                        password = password[0..^1];
                        int pos = Console.CursorLeft;

                        Console.SetCursorPosition(pos - 1, Console.CursorTop);
                        Console.Write(" ");

                        Console.SetCursorPosition(pos - 1, Console.CursorTop);
                    }
                }
                info = Console.ReadKey(true);
            }

            Console.WriteLine();
            return password;
        }
    }
}
