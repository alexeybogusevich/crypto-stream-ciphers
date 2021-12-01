using System;
using System.Text;

namespace KNU.Crypto.StreamCiphers.Transformations
{
    public static class Salsa20Transformation
    {
        public static uint Add32(uint a, uint b)
        {
            return unchecked(a + b);
        }

        public static uint RotateLeft(uint a, int b)
        {
            return (a << b) | (a >> (32 - b));
        }

        public static (uint, uint, uint, uint) QuarterRound(uint a, uint b, uint c, uint d)
        {
            b ^= RotateLeft(Add32(a, d), 7);
            c ^= RotateLeft(Add32(b, a), 9);
            d ^= RotateLeft(Add32(c, b), 13);
            a ^= RotateLeft(Add32(d, c), 18);

            return (a, b, c, d);
        }

        public static void RowRound(uint[] state)
        {
            if (state.Length != 16)
            {
                throw new ArgumentException("State array should always be 16 bytes");
            }
            for (int i = 0; i < 4; i++)
            {
                (state[4 * i + (i % 4)], state[4 * i + ((i + 1) % 4)], state[4 * i + ((i + 2) % 4)], state[4 * i + ((i + 3) % 4)]) = QuarterRound(state[4 * i + (i % 4)], state[4 * i + ((i + 1) % 4)], state[4 * i + ((i + 2) % 4)], state[4 * i + ((i + 3) % 4)]);
            }
        }

        public static void ColumnRound(uint[] state)
        {
            if (state.Length != 16)
            {
                throw new ArgumentException("State array should always be 16 bytes");
            }
            for (int i = 0; i < 4; i++)
            {
                (state[i + (4 * i) % 16], state[i + (4 * (i + 1)) % 16], state[i + (4 * (i + 2)) % 16], state[i + (4 * (i + 3)) % 16]) = QuarterRound(state[i + (4 * i) % 16], state[i + (4 * (i + 1)) % 16], state[i + (4 * (i + 2)) % 16], state[i + (4 * (i + 3)) % 16]);
            }
        }

        public static void DoubleRound(uint[] state)
        {
            ColumnRound(state);
            RowRound(state);
        }

        public static uint LittleEndian(byte[] input, int inputOffset)
        {
            return unchecked((uint)(((input[inputOffset] | (input[inputOffset + 1] << 8)) | (input[inputOffset + 2] << 16)) | (input[inputOffset + 3] << 24)));
        }

        public static void RevLittleEndian(uint input, byte[] output, int outputOffset)
        {
            unchecked
            {
                output[outputOffset] = (byte)input;
                output[outputOffset + 1] = (byte)(input >> 8);
                output[outputOffset + 2] = (byte)(input >> 16);
                output[outputOffset + 3] = (byte)(input >> 24);
            }
        }

        public static void IncrementSalsaState(uint[] state)
        {
            if (state.Length != 16)
            {
                throw new ArgumentException("State array should always be 16 bytes");
            }

            state[8] = Add32(state[8], 1);
            if (state[8] == 0)
            {
                state[9] = Add32(state[9], 1);
            }
        }

        private static readonly byte[] Const16 = Encoding.ASCII.GetBytes("expand 16-byte k");
        private static readonly byte[] Const32 = Encoding.ASCII.GetBytes("expand 32-byte k");

        public static uint[] CreateInitialState(byte[] key, byte[] iv)
        {
            byte[] constants = key.Length switch
            {
                16 => Const16,
                32 => Const32,
                _ => throw new ArgumentException($"Invalid key size: {key.Length}")
            };

            uint[] state = new uint[16]
            {
                LittleEndian(constants, 0),          LittleEndian(key, 0),              LittleEndian(key, 4),               LittleEndian(key, 8),
                LittleEndian(key, 12),               LittleEndian(constants, 4),        LittleEndian(iv, 0),                LittleEndian(iv, 4),
                0,                                   0,                                 LittleEndian(constants, 8),         LittleEndian(key, key.Length - 16),
                LittleEndian(key, key.Length - 12),  LittleEndian(key, key.Length - 8), LittleEndian(key, key.Length - 4),  LittleEndian(constants, 12)
            };

            return state;
        }

        public static void SalsaBlock(byte[] output, uint[] initialState, uint rounds = 20)
        {
            if (initialState.Length != 16)
            {
                throw new ArgumentException("State array should always be 16 bytes");
            }

            uint[] state = (uint[])initialState.Clone();

            for (int i = 0; i < Math.Floor((double)rounds / 2); i++)
            {
                DoubleRound(state);
            }

            for (int i = 0; i < initialState.Length; i++)
            {
                RevLittleEndian(Add32(state[i], initialState[i]), output, 4 * i);
            }
        }
    }
}
