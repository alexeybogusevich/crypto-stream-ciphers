using KNU.Crypto.SymmetricCiphers.AES.Implementation;
using System;

namespace KNU.Crypto.StreamCiphers.Encryptors
{
    public class OFB : BaseEncryptor
    {
        private readonly byte[] iv;

        public OFB(byte[] key, byte[] iv) : base(key, false)
        {
            this.iv = iv;
        }

        public override int TransformBlock(
            byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            var bytesEncrypted = 0;
            var transformationKey = (byte[])key.Clone();

            for (int i = 0; i < inputCount; i += InputBlockSize)
            {
                var algorithm = new Algorithm(transformationKey);
                byte[] output = algorithm.Encrypt(iv);
                output.CopyTo(iv, 0);

                byte[] input = new byte[InputBlockSize];
                Array.Copy(inputBuffer, inputOffset + i, input, 0, InputBlockSize);

                for (int j = 0; j < input.Length; j++)
                {
                    output[j] ^= input[j];
                }

                output.CopyTo(outputBuffer, outputOffset + i);

                bytesEncrypted += output.Length;
            }

            return bytesEncrypted;
        }
    }
}
