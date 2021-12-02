using System;

namespace KNU.Crypto.RC4.Ciphers
{
    public class Algorithm 
    {
        private readonly byte[] cipherKey;

        public Algorithm(byte[] key)
        {
            cipherKey = new byte[key.Length];
            key.CopyTo(cipherKey, 0);
        }

        public byte[] Decrypt(byte[] bytes)
        {
            return Apply(bytes, cipherKey);
        }

        public byte[] Encrypt(byte[] bytes)
        {
            return Apply(bytes, cipherKey);
        }

        private byte[] Apply(byte[] data, byte[] cipherKey)
        {
            int[] S = new int[256];
            for (int _ = 0; _ < 256; _++)
            {
                S[_] = _;
            }

            int[] T = new int[256];

            if (cipherKey.Length == 256)
            {
                Buffer.BlockCopy(cipherKey, 0, T, 0, cipherKey.Length);
            }
            else
            {
                for (int _ = 0; _ < 256; _++)
                {
                    T[_] = cipherKey[_ % cipherKey.Length];
                }
            }

            int i = 0;
            int j = 0;
            for (i = 0; i < 256; i++)
            {
                j = (j + S[i] + T[i]) % 256;

                int temp = S[i];
                S[i] = S[j];
                S[j] = temp;
            }


            i = j = 0;
            var result = new byte[data.Length];
            for (int iteration = 0; iteration < data.Length; iteration++)
            {
                i = (i + 1) % 256;

                j = (j + S[i]) % 256;

                int temp = S[i];
                S[i] = S[j];
                S[j] = temp;

                int K = S[(S[i] + S[j]) % 256];

                result[iteration] = Convert.ToByte(data[iteration] ^ K);
            }

            return result;
        }
    }
}
