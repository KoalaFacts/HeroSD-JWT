// Ported from Chaos.NaCl (https://github.com/CodesInChaos/Chaos.NaCl)
// Original Author: Dan Bernstein (djb) - Ref10 from SUPERCOP
// C# Port: Christian Winnerlein (CodesInChaos)
// License: Public Domain
//
// Field arithmetic operations for GF(2^255 - 19).
// All operations are performed in constant time to prevent timing attacks.

namespace HeroSdJwt.Internal.Ed25519;

/// <summary>
/// Field arithmetic operations for the field GF(2^255 - 19).
///
/// The field GF(2^255 - 19) is the underlying field for Curve25519/Ed25519.
/// Elements are represented in radix 2^25.5 using 10 signed 32-bit integers.
///
/// All operations are implemented to run in constant time to prevent timing attacks.
/// </summary>
internal static partial class FieldOperations
{
    /// <summary>
    /// Sets h to 0.
    /// </summary>
    internal static void FeZero(out FieldElement h)
    {
        h = default(FieldElement);
    }

    /// <summary>
    /// Sets h to 1.
    /// </summary>
    internal static void FeOne(out FieldElement h)
    {
        h = default(FieldElement);
        h.x0 = 1;
    }

    /// <summary>
    /// h = f + g
    /// </summary>
    internal static void FeAdd(out FieldElement h, ref FieldElement f, ref FieldElement g)
    {
        h.x0 = f.x0 + g.x0;
        h.x1 = f.x1 + g.x1;
        h.x2 = f.x2 + g.x2;
        h.x3 = f.x3 + g.x3;
        h.x4 = f.x4 + g.x4;
        h.x5 = f.x5 + g.x5;
        h.x6 = f.x6 + g.x6;
        h.x7 = f.x7 + g.x7;
        h.x8 = f.x8 + g.x8;
        h.x9 = f.x9 + g.x9;
    }

    /// <summary>
    /// h = f - g
    /// </summary>
    internal static void FeSub(out FieldElement h, ref FieldElement f, ref FieldElement g)
    {
        h.x0 = f.x0 - g.x0;
        h.x1 = f.x1 - g.x1;
        h.x2 = f.x2 - g.x2;
        h.x3 = f.x3 - g.x3;
        h.x4 = f.x4 - g.x4;
        h.x5 = f.x5 - g.x5;
        h.x6 = f.x6 - g.x6;
        h.x7 = f.x7 - g.x7;
        h.x8 = f.x8 - g.x8;
        h.x9 = f.x9 - g.x9;
    }

    /// <summary>
    /// h = -f
    /// </summary>
    internal static void FeNeg(out FieldElement h, ref FieldElement f)
    {
        h.x0 = -f.x0;
        h.x1 = -f.x1;
        h.x2 = -f.x2;
        h.x3 = -f.x3;
        h.x4 = -f.x4;
        h.x5 = -f.x5;
        h.x6 = -f.x6;
        h.x7 = -f.x7;
        h.x8 = -f.x8;
        h.x9 = -f.x9;
    }

    /// <summary>
    /// h = f
    /// </summary>
    internal static void FeCopy(out FieldElement h, ref FieldElement f)
    {
        h.x0 = f.x0;
        h.x1 = f.x1;
        h.x2 = f.x2;
        h.x3 = f.x3;
        h.x4 = f.x4;
        h.x5 = f.x5;
        h.x6 = f.x6;
        h.x7 = f.x7;
        h.x8 = f.x8;
        h.x9 = f.x9;
    }

    /// <summary>
    /// Replace (f,g) with (g,f) if b == 1;
    /// replace (f,g) with (f,g) if b == 0.
    ///
    /// Preconditions: b in {0,1}.
    /// </summary>
    internal static void FeCswap(ref FieldElement f, ref FieldElement g, int b)
    {
        int mask = -b; // mask = b ? 0xFFFFFFFF : 0x00000000

        int x0 = mask & (f.x0 ^ g.x0); f.x0 ^= x0; g.x0 ^= x0;
        int x1 = mask & (f.x1 ^ g.x1); f.x1 ^= x1; g.x1 ^= x1;
        int x2 = mask & (f.x2 ^ g.x2); f.x2 ^= x2; g.x2 ^= x2;
        int x3 = mask & (f.x3 ^ g.x3); f.x3 ^= x3; g.x3 ^= x3;
        int x4 = mask & (f.x4 ^ g.x4); f.x4 ^= x4; g.x4 ^= x4;
        int x5 = mask & (f.x5 ^ g.x5); f.x5 ^= x5; g.x5 ^= x5;
        int x6 = mask & (f.x6 ^ g.x6); f.x6 ^= x6; g.x6 ^= x6;
        int x7 = mask & (f.x7 ^ g.x7); f.x7 ^= x7; g.x7 ^= x7;
        int x8 = mask & (f.x8 ^ g.x8); f.x8 ^= x8; g.x8 ^= x8;
        int x9 = mask & (f.x9 ^ g.x9); f.x9 ^= x9; g.x9 ^= x9;
    }

    /// <summary>
    /// Replace (f,g) with (g,g) if b == 1;
    /// replace (f,g) with (f,g) if b == 0.
    ///
    /// Preconditions: b in {0,1}.
    /// </summary>
    internal static void FeCmov(ref FieldElement f, ref FieldElement g, int b)
    {
        int f0 = f.x0;
        int f1 = f.x1;
        int f2 = f.x2;
        int f3 = f.x3;
        int f4 = f.x4;
        int f5 = f.x5;
        int f6 = f.x6;
        int f7 = f.x7;
        int f8 = f.x8;
        int f9 = f.x9;
        int g0 = g.x0;
        int g1 = g.x1;
        int g2 = g.x2;
        int g3 = g.x3;
        int g4 = g.x4;
        int g5 = g.x5;
        int g6 = g.x6;
        int g7 = g.x7;
        int g8 = g.x8;
        int g9 = g.x9;
        int x0 = f0 ^ g0;
        int x1 = f1 ^ g1;
        int x2 = f2 ^ g2;
        int x3 = f3 ^ g3;
        int x4 = f4 ^ g4;
        int x5 = f5 ^ g5;
        int x6 = f6 ^ g6;
        int x7 = f7 ^ g7;
        int x8 = f8 ^ g8;
        int x9 = f9 ^ g9;
        b = -b;
        x0 &= b;
        x1 &= b;
        x2 &= b;
        x3 &= b;
        x4 &= b;
        x5 &= b;
        x6 &= b;
        x7 &= b;
        x8 &= b;
        x9 &= b;
        f.x0 = f0 ^ x0;
        f.x1 = f1 ^ x1;
        f.x2 = f2 ^ x2;
        f.x3 = f3 ^ x3;
        f.x4 = f4 ^ x4;
        f.x5 = f5 ^ x5;
        f.x6 = f6 ^ x6;
        f.x7 = f7 ^ x7;
        f.x8 = f8 ^ x8;
        f.x9 = f9 ^ x9;
    }

    // Note: The following operations (fe_mul, fe_sq, fe_tobytes, fe_frombytes, etc.)
    // are too large to include in this initial framework. They will be added in
    // the next phase of porting.
    //
    // Required for full Ed25519 support:
    // - fe_mul (field multiplication)
    // - fe_sq (field squaring)
    // - fe_sq2 (field squaring * 2)
    // - fe_tobytes (serialize to bytes)
    // - fe_frombytes (deserialize from bytes)
    // - fe_invert (field inversion)
    // - fe_pow22523 (exponentiation for sqrt)
    // - fe_isnonzero (check if nonzero)
    // - fe_isnegative (check if negative)
    //
    // Total: ~400 more lines of arithmetic code
}
