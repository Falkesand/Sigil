using System.Security.Cryptography;

namespace Sigil.Transparency;

/// <summary>
/// RFC 6962 Merkle tree algorithms with domain-separated hashing.
/// </summary>
public static class MerkleTree
{
    private const byte LeafPrefix = 0x00;
    private const byte NodePrefix = 0x01;

    public static byte[] ComputeLeafHash(byte[] data)
    {
        var prefixed = new byte[1 + data.Length];
        prefixed[0] = LeafPrefix;
        data.CopyTo(prefixed, 1);
        return SHA256.HashData(prefixed);
    }

    public static byte[] ComputeNodeHash(byte[] left, byte[] right)
    {
        var prefixed = new byte[1 + left.Length + right.Length];
        prefixed[0] = NodePrefix;
        left.CopyTo(prefixed, 1);
        right.CopyTo(prefixed, 1 + left.Length);
        return SHA256.HashData(prefixed);
    }

    /// <summary>
    /// Computes the Merkle tree root hash per RFC 6962 Section 2.
    /// </summary>
    public static byte[] ComputeRoot(IReadOnlyList<byte[]> leafHashes)
    {
        if (leafHashes.Count == 0)
            return SHA256.HashData([]);

        return ComputeRootRecursive(leafHashes, 0, leafHashes.Count);
    }

    /// <summary>
    /// Returns the largest power of 2 strictly less than n (n must be > 1).
    /// </summary>
    public static int LargestPowerOf2LessThan(int n)
    {
        int k = 1;
        while (k < n) k <<= 1;
        return k >> 1;
    }

    /// <summary>
    /// Generates an inclusion proof for leaf at index m in a tree of n leaves (RFC 6962 Section 2.1.1).
    /// </summary>
    public static InclusionProof GenerateInclusionProof(int leafIndex, IReadOnlyList<byte[]> leafHashes)
    {
        var path = new List<byte[]>();
        InclusionPath(leafIndex, leafHashes, 0, leafHashes.Count, path);
        var rootHash = ComputeRoot(leafHashes);

        return new InclusionProof
        {
            LeafIndex = leafIndex,
            TreeSize = leafHashes.Count,
            RootHash = Convert.ToHexStringLower(rootHash),
            Hashes = path.Select(Convert.ToHexStringLower).ToList()
        };
    }

    /// <summary>
    /// Verifies an inclusion proof: recomputes root from leaf hash + proof path.
    /// </summary>
    public static bool VerifyInclusionProof(InclusionProof proof, byte[] leafHash)
    {
        // Replay the recursive descent to determine the path through the tree,
        // then combine hashes bottom-up.
        var index = (int)proof.LeafIndex;
        var size = (int)proof.TreeSize;

        // Record the descent: at each level, did the leaf go left (true) or right (false)?
        var wentLeft = new List<bool>();
        var remaining = size;
        var pos = index;
        while (remaining > 1)
        {
            var k = LargestPowerOf2LessThan(remaining);
            if (pos < k)
            {
                wentLeft.Add(true);
                remaining = k;
            }
            else
            {
                wentLeft.Add(false);
                pos -= k;
                remaining -= k;
            }
        }

        if (wentLeft.Count != proof.Hashes.Count)
            return false;

        // Combine bottom-up: path[0] is the innermost sibling, wentLeft[0] is outermost
        var hash = leafHash;
        for (int i = 0; i < proof.Hashes.Count; i++)
        {
            var sibling = Convert.FromHexString(proof.Hashes[i]);
            var levelFromBottom = wentLeft.Count - 1 - i;
            hash = wentLeft[levelFromBottom]
                ? ComputeNodeHash(hash, sibling)
                : ComputeNodeHash(sibling, hash);
        }

        return Convert.ToHexStringLower(hash) == proof.RootHash;
    }

    /// <summary>
    /// Generates a consistency proof between old tree (size m) and new tree (size n) per RFC 6962 Section 2.1.2.
    /// </summary>
    public static ConsistencyProof GenerateConsistencyProof(int oldSize, IReadOnlyList<byte[]> newLeafHashes)
    {
        var oldLeafHashes = newLeafHashes.Take(oldSize).ToList();
        var oldRoot = ComputeRoot(oldLeafHashes);
        var newRoot = ComputeRoot(newLeafHashes);

        var path = new List<byte[]>();
        if (oldSize > 0 && oldSize < newLeafHashes.Count)
            ConsistencyPath(oldSize, newLeafHashes, 0, newLeafHashes.Count, true, path);

        return new ConsistencyProof
        {
            OldSize = oldSize,
            NewSize = newLeafHashes.Count,
            OldRootHash = Convert.ToHexStringLower(oldRoot),
            NewRootHash = Convert.ToHexStringLower(newRoot),
            Hashes = path.Select(Convert.ToHexStringLower).ToList()
        };
    }

    /// <summary>
    /// Verifies a consistency proof: the old root can be computed from the proof,
    /// and the new root can also be computed from the proof.
    /// </summary>
    public static bool VerifyConsistencyProof(ConsistencyProof proof)
    {
        if (proof.OldSize == proof.NewSize)
            return proof.OldRootHash == proof.NewRootHash && proof.Hashes.Count == 0;

        if (proof.OldSize == 0)
            return proof.Hashes.Count == 0;

        var hashes = proof.Hashes.Select(h => Convert.FromHexString(h)).ToList();

        // Replay the decomposition to determine the combining structure
        var steps = new List<ConsistencyStep>();
        ReplayConsistencyPath((int)proof.OldSize, (int)proof.NewSize, true, steps);

        if (steps.Count != hashes.Count)
            return false;

        // When startFromOldRoot is true and m reaches a complete subtree,
        // the proof doesn't include that subtree's hash — it IS the old root.
        // In that case there's no Base step; we initialize from the old root hash.
        bool hasBase = steps.Contains(ConsistencyStep.Base);
        byte[] oldHash;
        byte[] newHash;

        int hashIdx = 0;
        if (hasBase)
        {
            oldHash = Array.Empty<byte>(); // will be set by Base step
            newHash = Array.Empty<byte>();
        }
        else
        {
            // Old tree is a complete left subtree; old root is the starting seed
            oldHash = Convert.FromHexString(proof.OldRootHash);
            newHash = Convert.FromHexString(proof.OldRootHash);
        }

        for (int i = 0; i < steps.Count; i++)
        {
            var step = steps[i];
            var h = hashes[hashIdx++];

            switch (step)
            {
                case ConsistencyStep.Base:
                    oldHash = h;
                    newHash = h;
                    break;

                case ConsistencyStep.RightSibling:
                    newHash = ComputeNodeHash(newHash, h);
                    break;

                case ConsistencyStep.LeftSibling:
                    oldHash = ComputeNodeHash(h, oldHash);
                    newHash = ComputeNodeHash(h, newHash);
                    break;
            }
        }

        return Convert.ToHexStringLower(oldHash) == proof.OldRootHash
            && Convert.ToHexStringLower(newHash) == proof.NewRootHash;
    }

    private enum ConsistencyStep { Base, RightSibling, LeftSibling }

    private static void ReplayConsistencyPath(int m, int n, bool startFromOldRoot, List<ConsistencyStep> steps)
    {
        if (m == n)
        {
            if (!startFromOldRoot)
                steps.Add(ConsistencyStep.Base);
            return;
        }

        var k = LargestPowerOf2LessThan(n);
        if (m <= k)
        {
            ReplayConsistencyPath(m, k, startFromOldRoot, steps);
            steps.Add(ConsistencyStep.RightSibling);
        }
        else
        {
            ReplayConsistencyPath(m - k, n - k, false, steps);
            steps.Add(ConsistencyStep.LeftSibling);
        }
    }

    private static void ConsistencyPath(int m, IReadOnlyList<byte[]> hashes, int start, int count, bool startFromOldRoot, List<byte[]> path)
    {
        if (m == count)
        {
            if (!startFromOldRoot)
                path.Add(ComputeRootRecursive(hashes, start, count));
            return;
        }

        var k = LargestPowerOf2LessThan(count);
        if (m <= k)
        {
            ConsistencyPath(m, hashes, start, k, startFromOldRoot, path);
            path.Add(ComputeRootRecursive(hashes, start + k, count - k));
        }
        else
        {
            ConsistencyPath(m - k, hashes, start + k, count - k, false, path);
            path.Add(ComputeRootRecursive(hashes, start, k));
        }
    }

    private static void InclusionPath(int m, IReadOnlyList<byte[]> hashes, int start, int count, List<byte[]> path)
    {
        if (count == 1)
            return;

        var k = LargestPowerOf2LessThan(count);
        if (m < k)
        {
            InclusionPath(m, hashes, start, k, path);
            path.Add(ComputeRootRecursive(hashes, start + k, count - k));
        }
        else
        {
            InclusionPath(m - k, hashes, start + k, count - k, path);
            path.Add(ComputeRootRecursive(hashes, start, k));
        }
    }

    private static byte[] ComputeRootRecursive(IReadOnlyList<byte[]> hashes, int start, int count)
    {
        if (count == 1)
            return hashes[start];

        var k = LargestPowerOf2LessThan(count);
        var left = ComputeRootRecursive(hashes, start, k);
        var right = ComputeRootRecursive(hashes, start + k, count - k);
        return ComputeNodeHash(left, right);
    }
}
