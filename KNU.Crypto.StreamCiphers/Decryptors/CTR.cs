using KNU.Crypto.StreamCiphers.Helpers;
using KNU.Crypto.SymmetricCiphers.AES.Implementation;
using System;
using System.Threading.Tasks;

namespace KNU.Crypto.StreamCiphers.Decryptors
{
    public class CTR : BaseDecryptor
    {
        private readonly byte[] iv;
        private int counter = 0;

        public CTR(byte[] key, byte[] iv, bool parallel = true) : base(key, parallel)
        {
            this.iv = iv;
        }

        public override int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            var bytesEncrypted = 0;

            if (parallel)
            {
                Parallel.For(0, inputCount / InputBlockSize, (i) =>
                {
                    byte[] input = new byte[InputBlockSize];
                    Array.Copy(inputBuffer, inputOffset + i * InputBlockSize, input, 0, InputBlockSize);

                    byte[] iv = new byte[InputBlockSize];
                    byte[] counterBytes = BitConverter.GetBytes(counter + i);
                    Array.Copy(iv, 0, iv, 0, 12);
                    Array.Copy(counterBytes, 0, iv, 12, 4);

                    byte[] transformationKey = (byte[])key.Clone();
                    var algorithm = new Algorithm(transformationKey);

                    byte[] output = algorithm.Decrypt(iv);

                    for (int j = 0; j < input.Length; j++)
                    {
                        output[j] ^= input[j];
                    }

                    if ((i + 1) * InputBlockSize >= inputCount)
                    {
                        output = PaddingManager.RemovePadding(output);
                    }

                    output.CopyTo(outputBuffer, outputOffset + i * InputBlockSize);
                    bytesEncrypted += output.Length;
                });
                counter = inputCount / InputBlockSize;
            }
            else
            {
                byte[] transformationKey = (byte[])key.Clone();
                for (int i = 0; i < inputCount; i += InputBlockSize)
                {
                    byte[] input = new byte[InputBlockSize];
                    Array.Copy(inputBuffer, inputOffset + i, input, 0, InputBlockSize);

                    byte[] iv = new byte[InputBlockSize];
                    byte[] counterBytes = BitConverter.GetBytes(counter);
                    Array.Copy(iv, 0, iv, 0, 12);
                    Array.Copy(counterBytes, 0, iv, 12, 4);

                    var algorithm = new Algorithm(transformationKey);
                    byte[] output = algorithm.Decrypt(iv);

                    for (int j = 0; j < input.Length; j++)
                    {
                        output[j] ^= input[j];
                    }

                    if (i + InputBlockSize >= inputCount)
                    {
                        output = PaddingManager.RemovePadding(output);
                    }

                    output.CopyTo(outputBuffer, outputOffset + i);
                    bytesEncrypted += output.Length;
                    counter += 1;
                }
            }

            return bytesEncrypted;
        }
    }
}
