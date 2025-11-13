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
    /// Compares two bytes for equality in constant time.
    /// </summary>
    /// <returns>1 if equal, 0 otherwise</returns>
    private static byte Equal(byte b, byte c)
    {
        byte ub = b;
        byte uc = c;
        byte x = (byte)(ub ^ uc); // 0: yes; 1..255: no
        uint y = x; // 0: yes; 1..255: no
        unchecked { y -= 1; } // 4294967295: yes; 0..254: no
        y >>= 31; // 1: yes; 0: no
        return (byte)y;
    }

    /// <summary>
    /// Checks if a signed byte is negative in constant time.
    /// </summary>
    /// <returns>1 if negative, 0 otherwise</returns>
    private static byte Negative(sbyte b)
    {
        ulong x = unchecked((ulong)(long)b); // 18446744073709551361..18446744073709551615: yes; 0..255: no
        x >>= 63; // 1: yes; 0: no
        return (byte)x;
    }

    /// <summary>
    /// Conditionally moves precomputed group element based on flag.
    /// </summary>
    private static void Cmov(ref GroupElementPreComp t, ref GroupElementPreComp u, byte b)
    {
        FieldOperations.FeCmov(ref t.yplusx, ref u.yplusx, b);
        FieldOperations.FeCmov(ref t.yminusx, ref u.yminusx, b);
        FieldOperations.FeCmov(ref t.xy2d, ref u.xy2d, b);
    }

    /// <summary>
    /// Selects a precomputed multiple of the base point from lookup tables.
    /// </summary>
    private static void Select(out GroupElementPreComp t, int pos, sbyte b)
    {
        GroupElementPreComp minust;
        byte bnegative = Negative(b);
        byte babs = (byte)(b - (((-bnegative) & b) << 1));

        GePrecompZero(out t);
        var table = LookupTables.Base[pos];
        Cmov(ref t, ref table[0], Equal(babs, 1));
        Cmov(ref t, ref table[1], Equal(babs, 2));
        Cmov(ref t, ref table[2], Equal(babs, 3));
        Cmov(ref t, ref table[3], Equal(babs, 4));
        Cmov(ref t, ref table[4], Equal(babs, 5));
        Cmov(ref t, ref table[5], Equal(babs, 6));
        Cmov(ref t, ref table[6], Equal(babs, 7));
        Cmov(ref t, ref table[7], Equal(babs, 8));
        minust.yplusx = t.yminusx;
        minust.yminusx = t.yplusx;
        FieldOperations.FeNeg(out minust.xy2d, ref t.xy2d);
        Cmov(ref t, ref minust, bnegative);
    }

    /// <summary>
    /// Scalar multiplication of the base point: h = a * B
    /// where a = a[0]+256*a[1]+...+256^31 a[31]
    /// B is the Ed25519 base point (x,4/5) with x positive.
    ///
    /// Preconditions:
    ///   a[31] &lt;= 127
    /// </summary>
    internal static void GeScalarmultBase(out GroupElementP3 h, byte[] a, int offset)
    {
        sbyte[] e = new sbyte[64];
        sbyte carry;
        GroupElementP1P1 r;
        GroupElementP2 s;
        GroupElementPreComp t;
        int i;

        // Convert scalar to signed nibbles (4-bit values)
        for (i = 0; i < 32; ++i)
        {
            e[2 * i + 0] = (sbyte)((a[offset + i] >> 0) & 15);
            e[2 * i + 1] = (sbyte)((a[offset + i] >> 4) & 15);
        }
        // Each e[i] is between 0 and 15
        // e[63] is between 0 and 7

        // Recode to signed digits in range [-8, 8]
        carry = 0;
        for (i = 0; i < 63; ++i)
        {
            e[i] += carry;
            carry = (sbyte)(e[i] + 8);
            carry >>= 4;
            e[i] -= (sbyte)(carry << 4);
        }
        e[63] += carry;
        // Each e[i] is now between -8 and 8

        // Process odd indices first
        GeP3Zero(out h);
        for (i = 1; i < 64; i += 2)
        {
            Select(out t, i / 2, e[i]);
            GeMadd(out r, ref h, ref t);
            GeP1P1ToP3(out h, ref r);
        }

        // Four doublings
        GeP3Dbl(out r, ref h); GeP1P1ToP2(out s, ref r);
        GeP2Dbl(out r, ref s); GeP1P1ToP2(out s, ref r);
        GeP2Dbl(out r, ref s); GeP1P1ToP2(out s, ref r);
        GeP2Dbl(out r, ref s); GeP1P1ToP3(out h, ref r);

        // Process even indices
        for (i = 0; i < 64; i += 2)
        {
            Select(out t, i / 2, e[i]);
            GeMadd(out r, ref h, ref t);
            GeP1P1ToP3(out h, ref r);
        }
    }

    /// <summary>
    /// Scalar multiplication: h = a * p
    ///
    /// Multiplies an arbitrary point p by scalar a.
    /// Uses simple double-and-add algorithm.
    /// </summary>
    internal static void GeScalarmult(out GroupElementP2 h, byte[] a, ref GroupElementP3 p)
    {
        // Start with identity
        GeP2Zero(out h);

        GroupElementP3 result;
        GeP3Zero(out result);

        // Double-and-add algorithm
        for (int i = 255; i >= 0; i--)
        {
            // Double
            GroupElementP1P1 t;
            GeP3Dbl(out t, ref result);
            GeP1P1ToP3(out result, ref t);

            // Get bit i of scalar
            int bit = (a[i / 8] >> (i % 8)) & 1;

            // If bit is 1, add p
            if (bit == 1)
            {
                GroupElementCached pCached;
                GeP3ToCached(out pCached, ref p);
                GeAdd(out t, ref result, ref pCached);
                GeP1P1ToP3(out result, ref t);
            }
        }

        // Convert to P2
        GeP3ToP2(out h, ref result);
    }

    /// <summary>
    /// Converts a scalar to sliding window representation.
    /// This representation reduces the number of point additions needed.
    /// </summary>
    private static void Slide(sbyte[] r, byte[] a)
    {
        int i;
        int b;
        int k;

        for (i = 0; i < 256; ++i)
            r[i] = (sbyte)(1 & (a[i >> 3] >> (i & 7)));

        for (i = 0; i < 256; ++i)
            if (r[i] != 0)
            {
                for (b = 1; b <= 6 && i + b < 256; ++b)
                {
                    if (r[i + b] != 0)
                    {
                        if (r[i] + (r[i + b] << b) <= 15)
                        {
                            r[i] += (sbyte)(r[i + b] << b); r[i + b] = 0;
                        }
                        else if (r[i] - (r[i + b] << b) >= -15)
                        {
                            r[i] -= (sbyte)(r[i + b] << b);
                            for (k = i + b; k < 256; ++k)
                            {
                                if (r[k] == 0)
                                {
                                    r[k] = 1;
                                    break;
                                }
                                r[k] = 0;
                            }
                        }
                        else
                            break;
                    }
                }
            }
    }

    /// <summary>
    /// Double scalar multiplication using Shamir's trick: r = a*A + b*B
    /// where A is an arbitrary point and B is the base point.
    ///
    /// This interleaved algorithm is more efficient than computing a*A and b*B
    /// separately and then adding them.
    ///
    /// Used in signature verification.
    /// </summary>
    internal static void GeDoubleScalarmultVartime(
        out GroupElementP2 r,
        byte[] a, ref GroupElementP3 A,
        byte[] b)
    {
        sbyte[] aSlide = new sbyte[256];
        sbyte[] bSlide = new sbyte[256];
        GroupElementCached[] Ai = new GroupElementCached[8];
        GroupElementCached[] Bi = new GroupElementCached[8];  // Bi also needs odd multiples
        GroupElementP1P1 t;
        GroupElementP3 u;
        GroupElementP3 A2;
        GroupElementP3 B;
        GroupElementP3 B2;
        int i;

        Slide(aSlide, a);
        Slide(bSlide, b);

        // Get base point B
        B = LookupTables.GetBasePoint();

        // Precompute Ai = [1A, 3A, 5A, 7A, 9A, 11A, 13A, 15A]
        GeP3ToCached(out Ai[0], ref A);
        GeP3Dbl(out t, ref A); GeP1P1ToP3(out A2, ref t);
        GeAdd(out t, ref A2, ref Ai[0]); GeP1P1ToP3(out u, ref t);
        GeP3ToCached(out Ai[1], ref u);
        GeAdd(out t, ref A2, ref Ai[1]); GeP1P1ToP3(out u, ref t);
        GeP3ToCached(out Ai[2], ref u);
        GeAdd(out t, ref A2, ref Ai[2]); GeP1P1ToP3(out u, ref t);
        GeP3ToCached(out Ai[3], ref u);
        GeAdd(out t, ref A2, ref Ai[3]); GeP1P1ToP3(out u, ref t);
        GeP3ToCached(out Ai[4], ref u);
        GeAdd(out t, ref A2, ref Ai[4]); GeP1P1ToP3(out u, ref t);
        GeP3ToCached(out Ai[5], ref u);
        GeAdd(out t, ref A2, ref Ai[5]); GeP1P1ToP3(out u, ref t);
        GeP3ToCached(out Ai[6], ref u);
        GeAdd(out t, ref A2, ref Ai[6]); GeP1P1ToP3(out u, ref t);
        GeP3ToCached(out Ai[7], ref u);

        // Precompute Bi = [1B, 3B, 5B, 7B, 9B, 11B, 13B, 15B]
        GeP3ToCached(out Bi[0], ref B);
        GeP3Dbl(out t, ref B); GeP1P1ToP3(out B2, ref t);
        GeAdd(out t, ref B2, ref Bi[0]); GeP1P1ToP3(out u, ref t);
        GeP3ToCached(out Bi[1], ref u);
        GeAdd(out t, ref B2, ref Bi[1]); GeP1P1ToP3(out u, ref t);
        GeP3ToCached(out Bi[2], ref u);
        GeAdd(out t, ref B2, ref Bi[2]); GeP1P1ToP3(out u, ref t);
        GeP3ToCached(out Bi[3], ref u);
        GeAdd(out t, ref B2, ref Bi[3]); GeP1P1ToP3(out u, ref t);
        GeP3ToCached(out Bi[4], ref u);
        GeAdd(out t, ref B2, ref Bi[4]); GeP1P1ToP3(out u, ref t);
        GeP3ToCached(out Bi[5], ref u);
        GeAdd(out t, ref B2, ref Bi[5]); GeP1P1ToP3(out u, ref t);
        GeP3ToCached(out Bi[6], ref u);
        GeAdd(out t, ref B2, ref Bi[6]); GeP1P1ToP3(out u, ref t);
        GeP3ToCached(out Bi[7], ref u);

        GeP2Zero(out r);

        // Find highest non-zero position
        for (i = 255; i >= 0; --i)
        {
            if ((aSlide[i] != 0) || (bSlide[i] != 0)) break;
        }

        // Interleaved double-and-add
        for (; i >= 0; --i)
        {
            GeP2Dbl(out t, ref r);

            if (aSlide[i] > 0)
            {
                GeP1P1ToP3(out u, ref t);
                GeAdd(out t, ref u, ref Ai[aSlide[i] / 2]);
            }
            else if (aSlide[i] < 0)
            {
                GeP1P1ToP3(out u, ref t);
                GeSub(out t, ref u, ref Ai[(-aSlide[i]) / 2]);
            }

            if (bSlide[i] > 0)
            {
                GeP1P1ToP3(out u, ref t);
                GeAdd(out t, ref u, ref Bi[bSlide[i] / 2]);
            }
            else if (bSlide[i] < 0)
            {
                GeP1P1ToP3(out u, ref t);
                GeSub(out t, ref u, ref Bi[(-bSlide[i]) / 2]);
            }

            GeP1P1ToP2(out r, ref t);
        }
    }
}
