using KNU.Crypto.StreamCiphers.Helpers;
using KNU.Crypto.SymmetricCiphers.AES.Implementation;
using System;
using System.Threading.Tasks;

namespace KNU.Crypto.StreamCiphers.Decryptors
{
    public class CFB : BaseDecryptor
    {
        private readonly byte[] iv;

        public CFB(byte[] key, byte[] iv, bool parallel = true) : base(key, parallel)
        {
            this.iv = iv;
        }

        public override int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            var bytesDecrypted = 0;
            var transformationKey = (byte[])key.Clone();

            if (parallel)
            {
                Parallel.For(0, inputCount / InputBlockSize, (i) =>
                {
                    byte[] input = new byte[InputBlockSize];
                    Array.Copy(inputBuffer, inputOffset + i * InputBlockSize, input, 0, InputBlockSize);
                    byte[] iv = new byte[InputBlockSize];
                    if (i == 0)
                    {
                        iv = (byte[])iv.Clone();
                    }
                    else
                    {
                        Array.Copy(inputBuffer, inputOffset + (i - 1) * InputBlockSize, iv, 0, InputBlockSize);
                    }

                    var algorithm = new Algorithm(transformationKey);
                    byte[] output = algorithm.Decrypt(iv);

                    for (int j = 0; j < output.Length; j++)
                    {
                        output[j] ^= input[j];
                    }

                    if ((i + 1) * InputBlockSize >= inputCount)
                    {
                        output = PaddingManager.RemovePadding(output);
                    }

                    output.CopyTo(outputBuffer, outputOffset + i * InputBlockSize);
                    bytesDecrypted += output.Length;
                });
            }
            else
            {
                for (int i = 0; i < inputCount; i += InputBlockSize)
                {
                    var algorithm = new Algorithm(transformationKey);
                    byte[] output = algorithm.Decrypt(iv);

                    byte[] input = new byte[InputBlockSize];
                    Array.Copy(inputBuffer, inputOffset + i, input, 0, InputBlockSize);

                    for (int j = 0; j < output.Length; j++)
                    {
                        output[j] ^= input[j];
                    }

                    if (i + InputBlockSize >= inputCount)
                    {
                        output = PaddingManager.RemovePadding(output);
                    }

                    output.CopyTo(outputBuffer, outputOffset + i);
                    input.CopyTo(iv, 0);

                    bytesDecrypted += output.Length;
                }
            }

            return bytesDecrypted;
        }
    }
}
