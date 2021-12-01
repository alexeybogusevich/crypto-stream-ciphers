using KNU.Crypto.StreamCiphers.Transformations;
using System;
using System.Security.Cryptography;

namespace KNU.Crypto.StreamCiphers.Encryptors
{
    public class Salsa20 : ICryptoTransform
    {
        protected uint[] state;
        protected uint rounds;

        public Salsa20(byte[] key, byte[] iv, uint rounds)
        {
            if (key.Length != 16 && key.Length != 32)
            {
                throw new ArgumentException($"Key length not supported: {key.Length}");
            }

            if (iv.Length < 8)
            {
                throw new ArgumentException($"Invalid initialization vector size: {iv.Length}");
            }

            this.rounds = rounds;
            state = Salsa20Transformation.CreateInitialState(key, iv);
        }

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            byte[] tempBuffer = new byte[64];
            int encryptedBytes = 0;

            while (inputCount > 0)
            {
                Salsa20Transformation.SalsaBlock(tempBuffer, state, rounds);
                Salsa20Transformation.IncrementSalsaState(state);

                int blockSize = Math.Min(InputBlockSize, inputCount);
                for (int i = 0; i < blockSize; i++)
                {
                    outputBuffer[outputOffset + i] = (byte)(inputBuffer[inputOffset + i] ^ tempBuffer[i]);
                }

                encryptedBytes += blockSize;

                inputCount -= InputBlockSize;
                outputOffset += InputBlockSize;
                inputOffset += InputBlockSize;
            }

            return encryptedBytes;
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            byte[] output = new byte[inputCount];
            TransformBlock(inputBuffer, inputOffset, inputCount, output, 0);
            return output;
        }

        public bool CanReuseTransform => false;

        public bool CanTransformMultipleBlocks => true;

        public int InputBlockSize => 16 * sizeof(uint);

        public int OutputBlockSize => 16 * sizeof(uint);

        public void Dispose()
        {
            if (state != null)
            {
                Array.Clear(state, 0, state.Length);
            }
            state = null;
        }
    }
}
