using KNU.Crypto.SymmetricCiphers.AES.Implementation;
using System;

namespace KNU.Crypto.StreamCiphers.Encryptors
{
    public class CBC : BaseEncryptor
    {
        private readonly byte[] iv;

        public CBC(byte[] key, byte[] iv, bool parallel = false) : base(key, parallel)
        {
            this.iv = iv;
        }

        public override int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            var bytesEncrypted = 0;
            var transformationKey = (byte[])key.Clone();
            var algorithm = new Algorithm(transformationKey);

            for (int i = 0; i < inputCount; i += InputBlockSize)
            {
                byte[] input = new byte[InputBlockSize];
                Array.Copy(inputBuffer, inputOffset + i, input, 0, InputBlockSize);

                for (int j = 0; j < input.Length; j++)
                {
                    input[j] ^= iv[j];
                }

                byte[] output = algorithm.Encrypt(input);

                output.CopyTo(outputBuffer, outputOffset + i);
                output.CopyTo(iv, 0);

                bytesEncrypted += output.Length;
            }

            return bytesEncrypted;
        }
    }
}
