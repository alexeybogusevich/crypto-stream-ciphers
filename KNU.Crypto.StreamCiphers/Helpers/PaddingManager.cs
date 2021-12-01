using System.Linq;

namespace KNU.Crypto.StreamCiphers.Helpers
{
    public static class PaddingManager
    {
        public static byte[] RemovePadding(byte[] output)
        {
            int k = output.Length - 1;
            while (k >= 0 && output[k] == 0) { k--; }
            if (k >= 0 && output[k] == 0x80)
            {
                output = output.Take(k).ToArray();
            }
            return output;
        }
    }
}
