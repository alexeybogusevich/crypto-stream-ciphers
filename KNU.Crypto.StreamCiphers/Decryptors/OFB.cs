using KNU.Crypto.StreamCiphers.Helpers;
using KNU.Crypto.SymmetricCiphers.AES.Implementation;
using System;

namespace KNU.Crypto.StreamCiphers.Decryptors
{
    public class OFB : BaseDecryptor
    {
        private readonly byte[] iv;

        public OFB(byte[] key, byte[] iv) : base(key, false)
        {
            this.iv = iv;
        }

        public override int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            var bytesDecrypted = 0;
            var transformationKey = (byte[])key.Clone();

            for (int i = 0; i < inputCount; i += InputBlockSize)
            {
                var algorithm = new Algorithm(transformationKey);

                byte[] output = algorithm.Decrypt(iv);
                output.CopyTo(iv, 0);

                byte[] input = new byte[InputBlockSize];
                Array.Copy(inputBuffer, inputOffset + i, input, 0, InputBlockSize);

                for (int j = 0; j < input.Length; j++)
                {
                    output[j] ^= input[j];
                }

                if (i + InputBlockSize >= inputCount)
                {
                    output = PaddingManager.RemovePadding(output);
                }

                output.CopyTo(outputBuffer, outputOffset + i);

                bytesDecrypted += output.Length;
            }

            return bytesDecrypted;
        }
    }
}
