using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Reflection;

namespace Bluecrypt
{
    internal class Program
    {
        private static readonly byte[] buffer = new byte[short.MaxValue], salt = new byte[ushort.MaxValue];
        private static readonly int Iterations = 70000;
        private static int Read;

        private static Aes Aes = Aes.Create();
        private static bool UseHashChecker;

        private static Version version = Assembly.GetExecutingAssembly().GetName().Version;

        private static void Main(string[] args)
        {
            //Generate hash and save it in a text file.
            if (args.Contains("--generate-hash"))
                GenerateHash();
            else if (args.Contains("--hash"))
                UseHashChecker = true;
            else if (args.Contains("--version") || args.Contains("-v"))
            {
                Console.WriteLine($"Current version is {version.Major}.{version.Minor}.{version.Build}");
                Environment.Exit(0);
            }

            var password = GetAndVerifyPassword();

            Console.Clear();

            Console.Write("Do you wanna encrypt or decrypt?\n1: Encrypt \n2: Decrypt\nInput: ");
            string input = Console.ReadLine();

            Console.Write("Inputfile: ");
            string inputfile = Console.ReadLine();

            EnsureFileExist(ref inputfile);
            CheckHash(password);

            if (input == "1")
                EncryptFile(inputfile, password);
            else if (input == "2")
            {
                Console.Write("Outputfile: ");
                DecryptFile(inputfile, Console.ReadLine(), password);
            }
            Aes.Clear();

            Console.WriteLine($"Done, operation completed!\nVersion of Bluecrypt: {version.Major}.{version.Minor}.{version.Build}\nAES\nKeysize: {Aes.Key.Length*8}\nCipherMode: {Aes.Mode}\nPadding: {Aes.Padding}");
            Console.ReadLine();
        }

        private static void EncryptFile(string inputFile, string password)
        {
            CheckIfEnoughStorageIsAvailable(inputFile, inputFile);

            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
                for (int i = 0; i < 10; i++)
                    rng.GetBytes(salt);

            Rfc2898DeriveBytes mykey = GetKey(password);
            using FileStream fsIn = new FileStream(inputFile, FileMode.Open, FileAccess.Read);

            if (inputFile.EndsWith("encrypted"))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                throw new Exception($"{inputFile} already exists! Please rename it or choose another name!");
            }

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
            CheckIfEnoughStorageIsAvailable(inputFile, outputFile);

            using FileStream fsCrypt = new FileStream(inputFile, FileMode.Open);
            fsCrypt.Read(salt, 0, salt.Length);

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

            if (!File.Exists(inputfile) && RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                inputfile = inputfile[..^1];

            if (inputfile.EndsWith("\"") || inputfile.EndsWith("\'"))
                inputfile = inputfile[..^1];

            if (inputfile.Contains("\'\\\'"))
                inputfile = inputfile.Replace("\'\\\'", "");

            if (!File.Exists(inputfile))
                throw new FileNotFoundException($"Operation aborted!\nFile does not exist!\nCouldn't find: {inputfile}");
        }

        private static void CheckIfEnoughStorageIsAvailable(string input, string destinationDrive)
        {
            DriveInfo osDrive = new DriveInfo(new FileInfo(destinationDrive).DirectoryName ?? throw new Exception($"{destinationDrive} could not be found"));
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

        private static void CheckHash(string password)
        {
            if (!UseHashChecker)
                return;

            Console.Write("hash file (leave empty to skip): ");
            string hashfile = Console.ReadLine();

            if (!string.IsNullOrWhiteSpace(hashfile))
                EnsureFileExist(ref hashfile);

            if (File.Exists(hashfile))
            {
                var strm = new StreamReader(hashfile!);

                if (CompareHash(CalcSha512(password), strm))
                    return;

                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Wrong password!!!\nComputed hash is not the same as provided in the file!!!\nAborting!!!");
                Console.ResetColor();

                throw new Exception("Wrong password or wrong hashfile provided.");
            }

            Console.Write("No hash file has been included. Do you still want to proceed? (y/n): ");
            string userinput = Console.ReadLine()?.ToLower();

            switch (userinput)
            {
                case "y":
                    break;
                case "n":
                    throw new Exception("Aborted by user");
                default:
                    throw new Exception("Wrong input");
            }
        }
        
        private static string CalcSha512(string str)
        {
            using var sha = SHA512.Create();
            var bytes = Encoding.UTF8.GetBytes(str);

            var hashBytes = sha.ComputeHash(bytes);
            var stringBuilder = new StringBuilder(512/8*2);

            foreach (var b in hashBytes)
                stringBuilder.Append(b.ToString("X2"));

            var hash = stringBuilder.ToString();
            return hash;
        }

        private static bool CompareHash(string hash, StreamReader strm)
        {
            var originalHash = strm.ReadLine();
            strm.Close();
            return originalHash != null && originalHash.Equals(hash);
        }

        private static void GenerateHash()
        {
            Console.Write("Password for hash: ");
            string pw1 = GetPassword();

            Console.Write("Confirm password: ");
            string pw2 = GetPassword();

            while (!pw1.Equals(pw2))
            {
                Console.WriteLine("Wrong password\nRetry again\nConfirm password: ");
                pw2 = GetPassword();
            }

            string path = $"{AppDomain.CurrentDomain.BaseDirectory}{Path.DirectorySeparatorChar}passwordhashSHA512.txt";
            if (File.Exists(path))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write("passwordhashSHA512 exists already!\nDo you want to overwrite this file? (y/n): ");

                Console.ResetColor();
                string confirmation = Console.ReadLine();

                if (confirmation != null && confirmation.Contains("n"))
                {
                    Console.WriteLine("Aborting...");
                    Environment.Exit(0);
                }
            }

            var hashGen = new StreamWriter(path);
            hashGen.Write(CalcSha512(pw1));
            hashGen.Close();
            Console.Clear();

            UseHashChecker = true;
        }

        /// <summary>
        /// Returns the, from the user, provided password which also being confirmed twice and compared.
        /// </summary>
        /// <returns></returns>
        private static string GetAndVerifyPassword()
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

            return password;
        }
    }
}
