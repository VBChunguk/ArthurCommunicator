using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Zotca.Vbc.Comm.Utils
{
    /// <summary>
    /// 암호화를 수행하는 정적 클래스입니다.
    /// </summary>
    public static class Crypt
    {
        /// <summary>
        /// 암호화와 복호화에 사용되는 기본 키입니다.
        /// </summary>
        public static string DefaultKey = "011218525486l6u1";

        /// <summary>
        /// check_inspection 요청에 사용되는 키입니다.
        /// </summary>
        public static string CheckInspectionKey = "skdnuCme11part29";

        /// <summary>
        /// 바이트 배열로부터 데이터를 복호화합니다.
        /// </summary>
        /// <param name="data">복호화할 바이트 배열입니다.</param>
        /// <returns>복호화된 데이터입니다.</returns>
        public static byte[] Decrypt(byte[] data)
        {
            MemoryStream stream = new MemoryStream(data);
            return Decrypt(stream);
        }

        /// <summary>
        /// System.IO.Stream으로부터 데이터를 복호화합니다.
        /// </summary>
        /// <param name="data">복호화할 System.IO.Stream입니다.</param>
        /// <returns>복호화된 데이터입니다.</returns>
        public static byte[] Decrypt(Stream data)
        {
            return Decrypt(data, DefaultKey);
        }

        /// <summary>
        /// 지정된 키를 사용하여 System.IO.Stream으로부터 데이터를 복호화합니다.
        /// </summary>
        /// <param name="data">복호화할 System.IO.Stream입니다.</param>
        /// <param name="key">복호화에 사용할 키입니다.</param>
        /// <returns>복호화된 데이터입니다.</returns>
        public static byte[] Decrypt(Stream data, string key)
        {
            Aes aes = Aes.Create();
            aes.IV = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            aes.Key = Encoding.ASCII.GetBytes(key);
            aes.Padding = PaddingMode.PKCS7;
            aes.Mode = CipherMode.ECB;
            ICryptoTransform aesTransform = aes.CreateDecryptor();
            CryptoStream cryptStream = new CryptoStream(data, aesTransform, CryptoStreamMode.Read);
            MemoryStream aesOutputStream = new MemoryStream();
            while (true)
            {
                byte[] buffer = new byte[256];
                int read = cryptStream.Read(buffer, 0, 256);
                if (read <= 0) break;
                aesOutputStream.Write(buffer, 0, read);
            }
            aesOutputStream.Position = 0;
            byte[] ret = new byte[aesOutputStream.Length];
            aesOutputStream.Read(ret, 0, ret.Length);
            return ret;
        }

        /// <summary>
        /// 바이트 배열로부터 데이터를 암호화합니다.
        /// </summary>
        /// <param name="valBytes">암호화할 바이트 배열입니다.</param>
        /// <returns>암호화된 데이터입니다.</returns>
        public static byte[] Encrypt(byte[] valBytes)
        {
            Aes aes = Aes.Create();
            aes.IV = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            aes.Key = Encoding.ASCII.GetBytes(DefaultKey);
            aes.Padding = PaddingMode.PKCS7;
            aes.Mode = CipherMode.ECB;
            ICryptoTransform aesTransform = aes.CreateEncryptor();
            MemoryStream aesFinishedStream = new MemoryStream();
            CryptoStream cryptStream = new CryptoStream(aesFinishedStream, aesTransform, CryptoStreamMode.Write);
            cryptStream.Write(valBytes, 0, valBytes.Length);
            cryptStream.FlushFinalBlock();

            aesFinishedStream.Position = 0;
            byte[] ret = new byte[aesFinishedStream.Length];
            aesFinishedStream.Read(ret, 0, ret.Length);
            return ret;
        }

        /// <summary>
        /// 바이트 배열로부터 Base64 인코딩을 수행합니다.
        /// </summary>
        /// <param name="val">인코딩할 바이트 배열입니다.</param>
        /// <returns>Base64 인코딩된 데이터입니다.</returns>
        public static string Base64(byte[] val)
        {
            ToBase64Transform b64Transform = new ToBase64Transform();
            MemoryStream b64FinishedStream = new MemoryStream();
            int len = val.Length;
            int p = 0;
            while (true)
            {
                byte[] outputBuffer = new byte[b64Transform.OutputBlockSize];
                int read = len - p;
                if (read < b64Transform.InputBlockSize)
                {
                    outputBuffer = b64Transform.TransformFinalBlock(val, p, read);
                    b64FinishedStream.Write(outputBuffer, 0, outputBuffer.Length);
                    break;
                }
                else
                {
                    read = b64Transform.InputBlockSize;
                    b64Transform.TransformBlock(val, p, read, outputBuffer, 0);
                    b64FinishedStream.Write(outputBuffer, 0, b64Transform.OutputBlockSize);
                }
                p += read;
            }
            return Encoding.ASCII.GetString(b64FinishedStream.GetBuffer(), 0, (int)b64FinishedStream.Length);
        }

        /// <summary>
        /// 바이트 배열로부터 데이터를 암호화하고 Base64 인코딩을 수행합니다.
        /// </summary>
        /// <param name="val">암호화할 바이트 배열입니다.</param>
        /// <returns>암호화 후 Base64 인코딩된 데이터입니다.</returns>
        public static string EncryptAndBase64(byte[] val)
        {
            byte[] valBytes = Encrypt(val);
            return Base64(valBytes);
        }
    }
}
