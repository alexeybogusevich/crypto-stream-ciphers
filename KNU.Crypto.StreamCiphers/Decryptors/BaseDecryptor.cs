using System;
using System.Security.Cryptography;

namespace KNU.Crypto.StreamCiphers.Decryptors
{
    public abstract class BaseDecryptor : ICryptoTransform
    {
        protected readonly bool parallel;
        protected byte[] key;

        public BaseDecryptor(byte[] key, bool parallel)
        {
            this.parallel = parallel;
            this.key = new byte[key.Length];
            key.CopyTo(this.key, 0);
        }

        public bool CanReuseTransform => false;

        public bool CanTransformMultipleBlocks => true;

        public int InputBlockSize => 16;

        public int OutputBlockSize => 16;

        public abstract int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset);

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            if (inputCount == 0) return new byte[0];

            var tempBuffer = new byte[InputBlockSize];
            Array.Copy(inputBuffer, inputOffset, tempBuffer, 0, inputCount);

            var transformed = new byte[InputBlockSize];
            TransformBlock(tempBuffer, 0, InputBlockSize, transformed, 0);

            return transformed;
        }

        public void Dispose()
        {
            if (key != null)
            {
                Array.Clear(key, 0, key.Length);
            }

            key = null;
        }
    }
}
