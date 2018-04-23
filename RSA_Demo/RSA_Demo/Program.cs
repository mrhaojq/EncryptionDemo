using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static System.Console;

namespace RSA_Demo
{
    class Program
    {
        static void Main(string[] args)
        {
            //生成公钥私钥
            RSAKey rsaKey = RsaUtil.GetRSAKey();
            WriteLine($"PrivateKey:{rsaKey.PrivateKey}");
            WriteLine($"PublicKey:{rsaKey.PublicKey}");
            ReadKey();
        }
    }
}
