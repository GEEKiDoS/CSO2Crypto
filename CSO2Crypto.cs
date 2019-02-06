using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace CSO2Encrypt
{
    enum PkgCipher
    {
        Des = 1,
        Aes
    };

    class CSO2EfileCrypto
    {
        byte[][] s_PackageListKey = new byte[][] {
            new byte[] { 0x9A, 0xA6, 0xC7, 0x59, 0x18, 0xEA, 0xD0, 0x44, 0x83, 0xA3, 0x3A, 0x3E, 0xCE, 0xAF, 0x6F, 0x68 },
            new byte[] { 0xB6, 0xBA, 0x15, 0xC7, 0x77, 0x9D, 0x9C, 0x49, 0x84, 0x62, 0x2A, 0x9A, 0x8A, 0x61, 0x84, 0xA6 },
            new byte[] { 0x68, 0x55, 0x24, 0x24, 0x2B, 0xCB, 0x88, 0x4B, 0xA7, 0xA6, 0xD2, 0xC7, 0x94, 0xED, 0xE8, 0xD3 },
            new byte[] { 0x36, 0x24, 0xD6, 0x8C, 0x6C, 0xB8, 0xE1, 0x4A, 0xB1, 0x82, 0xC0, 0xA3, 0xDC, 0xE4, 0x16, 0xC8 }
        };

        byte[] s_EmptyIv16 = new byte[16];

        public byte[] EncryptBuffer(PkgCipher chiperMode, int flag, string fileName, byte[] inBuffer)
        {
            if (inBuffer is null)
                throw new ArgumentNullException("EncryptBuffer: pInBuffer is NULL");

            ICryptoTransform encryptor = null;

            switch (chiperMode)
            {
                case PkgCipher.Des:
                    DESCryptoServiceProvider desCryptoServiceProvider = new DESCryptoServiceProvider();
                    var eightByteKey = new byte[8];
                    var eightByteIV = new byte[8];

                    int i = 0;
                    foreach (var b in GeneratePkgListKey(flag, fileName))
                    {
                        eightByteKey[i] = b;
                        i++;

                        if (i >= 8)
                            break;
                    }

                    desCryptoServiceProvider.Mode = CipherMode.CBC;
                    desCryptoServiceProvider.IV = eightByteIV;
                    desCryptoServiceProvider.Key = eightByteKey;

                    encryptor = desCryptoServiceProvider.CreateEncryptor();
                    break;
                case PkgCipher.Aes:
                    RijndaelManaged rijndaelManaged = new RijndaelManaged();

                    rijndaelManaged.Mode = CipherMode.CBC;

                    rijndaelManaged.IV = s_EmptyIv16;
                    rijndaelManaged.Key = GeneratePkgListKey(3, fileName);

                    encryptor = rijndaelManaged.CreateEncryptor();
                    break;
                default:
                    throw new Exception("Unsupported crypto mode");
            }


            return encryptor.TransformFinalBlock(inBuffer, 0, inBuffer.Length);
        }

        public byte[] DecryptBuffer(PkgCipher chiperMode, int flag, string fileName, byte[] inBuffer)
        {
            if (inBuffer is null)
                throw new ArgumentNullException("DecryptBuffer: pInBuffer is NULL");

            ICryptoTransform decryptor = null;

            switch (chiperMode)
            {
                case PkgCipher.Des:
                    DESCryptoServiceProvider desCryptoServiceProvider = new DESCryptoServiceProvider();
                    var eightByteKey = new byte[8];
                    var eightByteIV = new byte[8];

                    int i = 0;
                    foreach (var b in GeneratePkgListKey(flag, fileName))
                    {
                        eightByteKey[i] = b;
                        i++;

                        if (i >= 8)
                            break;
                    }

                    desCryptoServiceProvider.Mode = CipherMode.CBC;
                    desCryptoServiceProvider.IV = eightByteIV;
                    desCryptoServiceProvider.Key = eightByteKey;

                    decryptor = desCryptoServiceProvider.CreateDecryptor();
                    break;
                case PkgCipher.Aes:
                    RijndaelManaged rijndaelManaged = new RijndaelManaged();

                    rijndaelManaged.Mode = CipherMode.CBC;

                    rijndaelManaged.IV = s_EmptyIv16;
                    rijndaelManaged.Key = GeneratePkgListKey(3, fileName);

                    decryptor = rijndaelManaged.CreateDecryptor();
                    break;
                default:
                    throw new Exception("Unsupported crypto mode");
            }


            return decryptor.TransformFinalBlock(inBuffer, 0, inBuffer.Length);
        }

        public byte[] GeneratePkgListKey(int key, string packageIndexName)
        {
            IncrementalHash md5 = IncrementalHash.CreateHash(HashAlgorithmName.MD5);
            md5.AppendData(new byte[] { 2, 0, 0, 0 });

            if (Convert.ToBoolean(key % 2))
            {
                md5.AppendData(s_PackageListKey[key / 2]);
                md5.AppendData(Encoding.Default.GetBytes(packageIndexName));
            }
            else
            {
                md5.AppendData(Encoding.Default.GetBytes(packageIndexName));
                md5.AppendData(s_PackageListKey[key / 2]);
            }

            return md5.GetHashAndReset();
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    struct CSO2EncFileHeader
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 10)]
        public string szChecksum;
        public ushort iVersion;
        public byte iEncryption;
        public byte iFlag;
        public uint iFileSize;

        public byte[] ToByteArray()
        {
            var arr = new byte[0x12];
            var pHeader = Marshal.AllocHGlobal(0x12);

            Marshal.StructureToPtr(this, pHeader, false);
            Marshal.Copy(pHeader, arr, 0, 0x12);
            Marshal.FreeHGlobal(pHeader);

            return arr;
        }

        public static CSO2EncFileHeader FromByteArray(byte[] arr)
        {
            if (arr.Length < 0x12)
                throw new ArgumentOutOfRangeException("Length is smaller than 0x12.");

            var pHeader = Marshal.AllocHGlobal(0x12);
            Marshal.Copy(arr, 0, pHeader, 0x12);
            var header = (CSO2EncFileHeader)Marshal.PtrToStructure(pHeader, typeof(CSO2EncFileHeader));
            Marshal.FreeHGlobal(pHeader);

            return header;
        }
    }
}
