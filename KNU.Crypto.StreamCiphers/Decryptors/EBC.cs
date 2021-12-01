using KNU.Crypto.StreamCiphers.Helpers;
using KNU.Crypto.SymmetricCiphers.AES.Implementation;
using System;
using System.Threading.Tasks;

namespace KNU.Crypto.StreamCiphers.Decryptors
{
    public class EBC : BaseDecryptor
    {
        public EBC(byte[] key, bool parallel = true) : base(key, parallel) { }

        public override int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            int bytesDecrypted = 0;

            if (parallel)
            {
                Parallel.For(0, inputCount / InputBlockSize, (i) =>
                {
                    byte[] input = new byte[InputBlockSize];
                    Array.Copy(inputBuffer, inputOffset + i * InputBlockSize, input, 0, InputBlockSize);

                    byte[] transformationKey = (byte[])key.Clone();
                    var algorithm = new Algorithm(transformationKey);

                    byte[] output = algorithm.Decrypt(input);

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
                    byte[] input = new byte[InputBlockSize];
                    Array.Copy(inputBuffer, inputOffset + i, input, 0, InputBlockSize);

                    byte[] transformationKey = (byte[])key.Clone();
                    var algorithm = new Algorithm(transformationKey);

                    byte[] output = algorithm.Decrypt(input);

                    if (i + InputBlockSize >= inputCount)
                    {
                        output = PaddingManager.RemovePadding(output);
                    }

                    output.CopyTo(outputBuffer, outputOffset + i);
                    bytesDecrypted += output.Length;
                }
            }

            return bytesDecrypted;
        }
    }
}
