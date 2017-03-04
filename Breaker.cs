using System;
using System.Text;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Linq;

namespace Hello {
class Breaker
{
    byte[] target;
    Dictionary<long, byte[]> collisionTargets = new Dictionary<long, byte[]>();
    ICryptoTransform encryptor, decryptor;

    private readonly Random rand = new Random();
    public Breaker(byte[] target)
    {
        this.target = target;
        var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        aes.BlockSize = 128;
        aes.KeySize = 128;
        aes.Key = new byte[16];
        encryptor = aes.CreateEncryptor();
        decryptor = aes.CreateDecryptor();
    }

    public Breaker(string target) : this(Encoding.ASCII.GetBytes(target))
    {
    }

    public void Run(int n)
    {
        PreCompute(n);
        var h = new Hasher();
        foreach(byte[] collision in Collide()) {
            Console.WriteLine(BitConverter.ToString(collision));
            if (!Enumerable.SequenceEqual(h.Hash(collision), h.Hash(target))) {
                throw new Exception("BAD");
            }
        }
    }

    void PreCompute(int n)
    {
        collisionTargets.Clear();
        System.Console.Write("Precomputing");
        var buffer = new byte[10];
        for (int j = 0; j < n; j++)
        {
            var targetable = new byte[16];
            rand.NextBytes(buffer);
            Buffer.BlockCopy(buffer, 0, targetable, 0, 10);
            decryptor.TransformBlock(targetable, 0, 16, targetable, 0);
            collisionTargets[TailSixToLong(targetable)] = targetable;
            if ((j & ((1 << 20) - 1)) == 0)
            {
                Console.Write(".");
            }
        }
        System.Console.WriteLine();
    }

    static long TailSixToLong(byte[] b)
    {
        int index = b.Length - 1;
        long result = 0;
        for (int sh = 0; sh < 6; sh++)
        {
            result += (long)b[index--] << (sh * 8);
        }
        return result;
    }

    private IEnumerable<byte[]> Collide()
    {
        var randBuffer = new byte[16];
        var after = new byte[16];
        while (true)
        {
            rand.NextBytes(randBuffer);
            Array.Clear(randBuffer, 10, 6);
            encryptor.TransformBlock(randBuffer, 0, 16, after, 0);
            long tail = TailSixToLong(after);
            if (!collisionTargets.ContainsKey(tail))
                continue;
            // after contains collidable tail
            byte[] tgt = collisionTargets[tail];
            // now compute the full member of the preimage
            byte[] collision = ComputeCollision(randBuffer, tgt);
            yield return collision;
        }
    }

    private byte[] ComputeCollision(byte[] before, byte[] after)
    {
        var state = new byte[16];
        Array.Copy(before, state, 16);
        encryptor.TransformBlock(state, 0, 16, state, 0);
        var diff = new byte[10];
        for(int i = 0; i < diff.Length; i++) {
            diff[i] = (byte)(state[i] ^ after[i]);
        }
        for(int i = 0; i < diff.Length; i++) {
            state[i] ^= diff[i];
        }
        encryptor.TransformBlock(state, 0, 16, state, 0);
        // state now contains 0 capacity
        var firstBlock = new byte[10];
        Buffer.BlockCopy(target, 0, firstBlock, 0, Math.Min(10, target.Length));
        // pad it:
        if (target.Length == 9) {
            firstBlock[9] = 0x81;
        } else if (target.Length < 9) {
            firstBlock[target.Length] = 0x80;
            firstBlock[9] = 0x01;
        }
        for(int i = 0; i < firstBlock.Length; i++) {
            firstBlock[i] ^= state[i];
        }
        var result = new byte[20 + Math.Max(10, target.Length)];
        Buffer.BlockCopy(before, 0, result, 0, 10);
        Buffer.BlockCopy(diff, 0, result, 10, 10);
        Buffer.BlockCopy(firstBlock, 0, result, 20, 10);
        if (target.Length > 10) {
            Buffer.BlockCopy(target, 10, result, 30, target.Length - 10);
        }
        return result;
    }
}
}