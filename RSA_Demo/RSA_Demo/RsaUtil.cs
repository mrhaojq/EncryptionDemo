using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace RSA_Demo
{
   public static class RsaUtil
    {
        //https://www.cnblogs.com/revealit/p/6094750.html
        const int DWKEYSIZE = 1024; 

        public static RSAKey GetRSAKey()
        {
            RSACryptoServiceProvider.UseMachineKeyStore = true;
            RSACryptoServiceProvider rsaProvider = new RSACryptoServiceProvider(DWKEYSIZE);
            RSAParameters paras = rsaProvider.ExportParameters(true);

            return new RSAKey()
            {
                PublicKey=ComponentKey(paras.Exponent,paras.Modulus),
                PrivateKey=ComponentKey(paras.D,paras.Modulus)
            };
        }

        private static string ComponentKey(byte[] b1, byte[] b2)
        {
            List<byte> list = new List<byte>();
            list.Add((byte)b1.Length);
            list.AddRange(b1);
            list.AddRange(b2);
            byte[] b = list.ToArray<byte>();

            return Convert.ToBase64String(b);
        }

        private static void ResolveKey(string key,out byte[] b1,out byte[] b2)
        {
            byte[] b = Convert.FromBase64String(key);

            int b1Length = b[0];
            b1 = new byte[b1Length];
            b2 = new byte[b.Length- b1Length - 1];

            for (int n=1,i = 0,j=0; n < b.Length; n++)
            {
                if (n<= b1Length)
                {
                    b1[i++] = b[n];
                }
                else
                {
                    b2[j++] = b[n];
                }
            }
        }

        public static string EncryptionString(string source, string key)
        {
            string encryptString = string.Empty;
            byte[] d;
            byte[] n;

            try
            {
                if (!CheckSourceValidate(source))
                {
                    throw new Exception("source string too long");
                    /*为何还有限制
                     * https://blog.csdn.net/taoxin52/article/details/53782470
                    *如果source过长可以将source分段加密 追加到StringBuilder中
                    *source差分的时候，建议已35个字符为一组
                    * RSA 一次加密的byte数量是有限制的
                    * 一般中文转换成3个或者4个byte
                    * 如果某个中文转换成3个byte 前两个byte 与后一个byte被差分到
                    * 两个段里加密，解密的时候就会出现乱码
                    * 另外在两个加密段之间添加特殊符合@解密的时候先用@差分
                    * 分段解密，在拼接成解密后的字符串
                    */
                }

                //解析这个密钥
                ResolveKey(key, out d, out n);
                BigInteger   biN = new BigInteger(n);
                BigInteger biD = new BigInteger(d);
                encryptString = EncryptionString(source,biD,biN);
            }
            catch (Exception)
            {
                encryptString = source;
            }

            return encryptString;
        }

        private static string EncryptionString(string source, BigInteger d, BigInteger n)
        {
            int len = source.Length;
            int len1 = 0;
            int blockLen = 0;

            if ((len%128)==0)
            {
                len1 = len / 128;
            }
            else
            {
                len1 = len / 128+1;
            }

            string block = "";
            StringBuilder result = new StringBuilder();
            for (int i = 0; i < len1; i++)
            {
                if (len>=128)
                {
                    blockLen = 128;
                }
                else
                {
                    blockLen = len;
                }

                block = source.Substring(i * 128, blockLen);

                byte[] oText = System.Text.Encoding.UTF8.GetBytes(block);
                BigInteger biText = new BigInteger(oText);
                //BigInteger biEnText=biText.modPow()

            }

            return result.ToString().TrimEnd('@');
        }

        /// <summary>
        /// 检查明文的有效性 DWKEYSIZE/8-11 长度之内为有效 中英文都算一个字符
        /// </summary>
        /// <param name="source"></param>
        /// <returns></returns>
        private static bool CheckSourceValidate(string source)
        {
            return (DWKEYSIZE / 8 - 11) >= source.Length;
        }
    }

    public struct RSAKey
    {
        public string PublicKey { get; set; }
        public string PrivateKey { get; set; }
    }
}
