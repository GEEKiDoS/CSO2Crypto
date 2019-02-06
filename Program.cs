using System;
using System.IO;
using System.Linq;
using static System.Console;

namespace CSO2Encrypt
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length < 1)
                WriteLine("No input file!");

            foreach (var input in args)
            {
                var fileInfo = new FileInfo(input);
                if (!fileInfo.Exists)
                    throw new FileNotFoundException("Input file is not exists");

                var file = File.ReadAllBytes(input);

                var header = CSO2EncFileHeader.FromByteArray(file);

                if (header.szChecksum == "000000000")
                {
                    WriteLine($"{fileInfo.Name} is encrypted! Decrypting...");

                    var crypto = new CSO2EfileCrypto();
                    var decrypted = crypto.DecryptBuffer((PkgCipher)Convert.ToInt32(header.iEncryption), header.iFlag, fileInfo.Name, file.Skip(0x12).ToArray<byte>());

                    var newExt = fileInfo.Extension.Replace(".e", ".");

                    File.WriteAllBytes(fileInfo.FullName.Replace(fileInfo.Extension, newExt), decrypted);

                    WriteLine("Done!");
                }
                else
                {
                    WriteLine($"{fileInfo.Name} is not encrypted! Encrypting with AES and flag 3...");

                    header.szChecksum = "000000000";
                    header.iEncryption = Convert.ToByte(PkgCipher.Aes);
                    header.iVersion = 2;
                    header.iFlag = 3;

                    var newExt = fileInfo.Extension.Replace(".", ".e");
                    var newName = fileInfo.Name.Replace(fileInfo.Extension, newExt);
                    WriteLine($"New name of input file is {newName}");

                    var crypto = new CSO2EfileCrypto();
                    var crypted = crypto.EncryptBuffer(PkgCipher.Aes, header.iFlag, newName, file);

                    header.iFileSize = Convert.ToUInt32(crypted.Length);

                    using (var fs = new FileStream(fileInfo.FullName.Replace(fileInfo.Name, newName),FileMode.CreateNew))
                    {
                        fs.Write(header.ToByteArray(), 0, 0x12);
                        fs.Write(crypted, 0, crypted.Length);
                    }
                }
            }

            WriteLine("Press any key to exit...");
            ReadKey();
        }
    }
}
