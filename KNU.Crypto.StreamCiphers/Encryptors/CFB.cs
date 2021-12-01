using KNU.Crypto.SymmetricCiphers.AES.Implementation;
using System;

namespace KNU.Crypto.StreamCiphers.Encryptors
{
    public class CFB : BaseEncryptor
    {

        private readonly byte[] iv;

        public CFB(byte[] key, byte[] iv) : base(key, false)
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
                byte[] output = algorithm.Encrypt(iv);

                byte[] input = new byte[InputBlockSize];
                Array.Copy(inputBuffer, inputOffset + i, input, 0, InputBlockSize);

                for (int j = 0; j < input.Length; j++)
                {
                    output[j] ^= input[j];
                }

                output.CopyTo(outputBuffer, outputOffset + i);
                output.CopyTo(iv, 0);

                bytesEncrypted += output.Length;
            }

            return bytesEncrypted;
        }
    }
}
