// Ported from Chaos.NaCl (https://github.com/CodesInChaos/Chaos.NaCl)
// Original Author: Dan Bernstein (djb) - Ref10 from SUPERCOP
// C# Port: Christian Winnerlein (CodesInChaos)
// License: Public Domain
//
// Scalar multiplication operations for Ed25519
//
// NOTE: This is a simplified implementation without full precomputed tables.
// The full optimized version with precomputed base point tables can be added later.

using System;

namespace HeroSdJwt.Internal.Ed25519;

internal static partial class GroupOperations
{
    /// <summary>
    /// Scalar multiplication of the base point: h = a * B
    /// where B is the Ed25519 base point.
    ///
    /// This is a basic implementation using double-and-add algorithm.
    /// TODO: Optimize with precomputed tables from Chaos.NaCl for 4x-8x speedup.
    /// </summary>
    internal static void ge_scalarmult_base(out GroupElementP3 h, byte[] a, int aoffset)
    {
        // Start with the identity element
        ge_p3_0(out h);

        // Base point (generator) of Ed25519
        // This is the standard Ed25519 base point from RFC 8032
        GroupElementP3 basePoint;
        byte[] basePointBytes = new byte[32];

        // Ed25519 base point y-coordinate (little-endian)
        // y = 4/5 mod p (standard Ed25519 base point)
        basePointBytes[0] = 0x58;
        basePointBytes[1] = 0x66;
        basePointBytes[2] = 0x66;
        basePointBytes[3] = 0x66;
        basePointBytes[4] = 0x66;
        basePointBytes[5] = 0x66;
        basePointBytes[6] = 0x66;
        basePointBytes[7] = 0x66;
        basePointBytes[8] = 0x66;
        basePointBytes[9] = 0x66;
        basePointBytes[10] = 0x66;
        basePointBytes[11] = 0x66;
        basePointBytes[12] = 0x66;
        basePointBytes[13] = 0x66;
        basePointBytes[14] = 0x66;
        basePointBytes[15] = 0x66;
        basePointBytes[16] = 0x66;
        basePointBytes[17] = 0x66;
        basePointBytes[18] = 0x66;
        basePointBytes[19] = 0x66;
        basePointBytes[20] = 0x66;
        basePointBytes[21] = 0x66;
        basePointBytes[22] = 0x66;
        basePointBytes[23] = 0x66;
        basePointBytes[24] = 0x66;
        basePointBytes[25] = 0x66;
        basePointBytes[26] = 0x66;
        basePointBytes[27] = 0x66;
        basePointBytes[28] = 0x66;
        basePointBytes[29] = 0x66;
        basePointBytes[30] = 0x66;
        basePointBytes[31] = 0x66;

        if (!ge_frombytes_negate_vartime(out basePoint, basePointBytes, 0))
        {
            throw new InvalidOperationException("Failed to decode Ed25519 base point");
        }

        // Perform scalar multiplication using double-and-add
        // Process scalar from most significant bit to least significant
        for (int i = 255; i >= 0; i--)
        {
            // Double the current point
            GroupElementP1P1 t;
            ge_p3_dbl(out t, ref h);
            ge_p1p1_to_p3(out h, ref t);

            // Get bit i of scalar a
            int byteIndex = aoffset + (i / 8);
            int bitIndex = i % 8;
            int bit = (a[byteIndex] >> bitIndex) & 1;

            // If bit is 1, add the base point
            if (bit == 1)
            {
                GroupElementCached basePointCached;
                ge_p3_to_cached(out basePointCached, ref basePoint);
                ge_add(out t, ref h, ref basePointCached);
                ge_p1p1_to_p3(out h, ref t);
            }
        }
    }

    /// <summary>
    /// Scalar multiplication: h = a * p
    ///
    /// Multiplies an arbitrary point p by scalar a.
    /// Uses simple double-and-add algorithm.
    /// </summary>
    internal static void ge_scalarmult(out GroupElementP2 h, byte[] a, ref GroupElementP3 p)
    {
        // Start with identity
        ge_p2_0(out h);

        GroupElementP3 result;
        ge_p3_0(out result);

        // Double-and-add algorithm
        for (int i = 255; i >= 0; i--)
        {
            // Double
            GroupElementP1P1 t;
            ge_p3_dbl(out t, ref result);
            ge_p1p1_to_p3(out result, ref t);

            // Get bit i of scalar
            int bit = (a[i / 8] >> (i % 8)) & 1;

            // If bit is 1, add p
            if (bit == 1)
            {
                GroupElementCached pCached;
                ge_p3_to_cached(out pCached, ref p);
                ge_add(out t, ref result, ref pCached);
                ge_p1p1_to_p3(out result, ref t);
            }
        }

        // Convert to P2
        ge_p3_to_p2(out h, ref result);
    }

    /// <summary>
    /// Double scalar multiplication: r = a*A + b*B
    /// where A is an arbitrary point and B is the base point.
    ///
    /// Used in signature verification.
    /// </summary>
    internal static void ge_double_scalarmult_vartime(
        out GroupElementP2 r,
        byte[] a, ref GroupElementP3 A,
        byte[] b)
    {
        // Compute aA
        GroupElementP2 aA;
        ge_scalarmult(out aA, a, ref A);

        // Compute bB
        GroupElementP3 bB;
        ge_scalarmult_base(out bB, b, 0);

        // Add aA + bB
        GroupElementP3 aA_p3;
        ge_p2_to_p3(out aA_p3, ref aA);

        GroupElementCached bB_cached;
        ge_p3_to_cached(out bB_cached, ref bB);

        GroupElementP1P1 t;
        ge_add(out t, ref aA_p3, ref bB_cached);

        ge_p1p1_to_p2(out r, ref t);
    }
}
