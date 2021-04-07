using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace ConsoleApp1
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine(Encrypt("biisuyk2Rkx3XJw", "6e8f7f3af89aa975078505f650f19374bdd8cbf6c9bfe8dbb5d43a7bfc31de0c", 1, "10"));
        }
        static string Encrypt(string word, string publicKeyStr, short PublicKeyId, string v)
        {
            var key = PseudoRandomBytes_get(32);
            var pubKey = StringToByteArray(publicKeyStr);
            var iv = new byte[12] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
            long time = new DateTimeOffset(DateTime.Now).ToUnixTimeSeconds();
            time = 1617801711L; //shit
            var sealedBox = Sodium.SealedPublicKeyBox.Create(key, pubKey);
            byte[] tag; 
            var encrypted = AesGcm256.encrypt(word, pubKey, iv, time, out tag);
            var payload = GeneratePayload(BitConverter.GetBytes(PublicKeyId), sealedBox, tag, encrypted); 
            string ToReturn = $"#:{v}:{time}:{payload}";
            Console.WriteLine(ToReturn);
            return ToReturn;
        }

        private static string GeneratePayload(byte[] PubKeyId, byte[] sealedBox, byte[] tag, string encrypted)
        {
            int CountOfElements = 0;
            int k = 0;
            int decrease = 0;
            PubKeyId = Or(PubKeyId, 0x01);
            var sealedBoxStrLenPacked = BitConverter.GetBytes(sealedBox.Length);
            var encryptedBytes = Encoding.ASCII.GetBytes(encrypted);
            CountOfElements += PubKeyId.Length + sealedBox.Length + sealedBoxStrLenPacked.Length + tag.Length + encryptedBytes.Length;
            var payloadBytesArr = new byte[CountOfElements];
            //concat arrays
            for (int i = 0; i < CountOfElements; i++)
            {
                
                if ((k == 0 && i == PubKeyId.Length + decrease ) ||
                    (k == 1 && i == sealedBoxStrLenPacked.Length + decrease ) ||
                    (k == 2 && i == sealedBox.Length + decrease) ||
                    (k == 3 && i == tag.Length + decrease) ||
                    (k == 4 && i == encryptedBytes.Length + decrease)
                    )
                {
                    decrease = i;
                    k++;
                }
                if (k == 0)
                    payloadBytesArr[i] = PubKeyId[i - decrease];
                if (k==1)
                    payloadBytesArr[i] = sealedBoxStrLenPacked[i - decrease];
                if (k==2)
                    payloadBytesArr[i] = sealedBox[i - decrease];
                if (k==3)
                    payloadBytesArr[i] = tag[i - decrease];
                if (k==4)
                    payloadBytesArr[i] = encryptedBytes[i - decrease];
            }
            return Convert.ToBase64String(payloadBytesArr);
        }

        private static byte[] Or(byte[] InVal, byte opperand)
        {
            for (int i = 0; i < InVal.Length; i++)
            {
                InVal[i] = (byte)(opperand | InVal[i]);
            }

            return InVal;
        }
        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }
        static byte[] PseudoRandomBytes_get(int bytes)
        {
            var random = new System.Random();
            var byteArray = new byte[bytes];
            random.NextBytes(byteArray);
            return byteArray;
        }

    }
}