using System;
using System.Security.Cryptography;
using System.Text;
using System.Linq;

namespace Hello
{
    public class Hasher
    {
        private ICryptoTransform csCrypt;
        private byte[] state = new byte[16];
        public Hasher()
        {
            var aes = Aes.Create();
            aes.Mode = CipherMode.ECB;
            aes.BlockSize = 128;
            aes.KeySize = 128;
            aes.Key = new byte[16];
            csCrypt = aes.CreateEncryptor();
        }

        void Reset()
        {
            Array.Clear(state, 0, state.Length);
        }

        void Ingest(byte[] block)
        {
            var newState = new byte[16];
            Array.Copy(block, newState, 10);
            for (int i = 0; i < newState.Length; i++)
            {
                newState[i] ^= state[i];
            }
            csCrypt.TransformBlock(newState, 0, 16, state, 0);
        }

        void FinalIngest(byte[] block)
        {
            var last = new byte[10];
            if (block.Length == 10)
            {
                Ingest(block);
                last[0] = 0x80;
                last[9] = 0x01;
            }
            else if (block.Length == 9)
            {
                Array.Copy(block, last, 9);
                last[9] = 0x81;
            }
            else
            {
                Array.Copy(block, last, block.Length);
                last[block.Length] = 0x80;
                last[9] = 0x01;
            }
            Ingest(last);
        }

        byte[] Squeeze()
        {
            var result = state.Take(10).ToArray();
            csCrypt.TransformBlock(state, 0, 16, state, 0);
            return result;
        }

        public byte[] Hash(byte[] input)
        {
            Reset();
            for (int i = 0; i < input.Length / 10; i++)
            {
                var block = new byte[10];
                Array.Copy(input, i * 10, block, 0, 10);
                Ingest(block);
            }
            var lastBlock = new byte[input.Length % 10];
            Array.Copy(input, (input.Length / 10) * 10, lastBlock, 0, input.Length % 10);
            FinalIngest(lastBlock);
            return Enumerable.Concat(Squeeze(), Squeeze()).ToArray();
        }

        public string Hash(string input)
        {
            var bInput = Encoding.ASCII.GetBytes(input);
            var result = Hash(bInput);
            return BitConverter.ToString(result);
        }

    }
}