// Ported from Chaos.NaCl (https://github.com/CodesInChaos/Chaos.NaCl)
// Original Author: Dan Bernstein (djb) - Ref10 from SUPERCOP
// C# Port: Christian Winnerlein (CodesInChaos)
// License: Public Domain
//
// Field elements are represented as 10 int32 values in radix 2^25.5
// This representation allows for efficient arithmetic without overflow.

using System;
using System.Runtime.InteropServices;

namespace HeroSdJwt.Internal.Ed25519;

/// <summary>
/// Represents an element of the field GF(2^255 - 19).
///
/// Field elements are represented as 10 signed 32-bit integers.
/// Arithmetic is performed in radix 2^25.5, which means:
/// - Elements at even indices (0,2,4,6,8) use 26 bits
/// - Elements at odd indices (1,3,5,7,9) use 25 bits
///
/// This representation enables efficient arithmetic without risk of overflow
/// during intermediate calculations.
/// </summary>
[StructLayout(LayoutKind.Explicit, Size = 40)]
internal struct FieldElement
{
    [FieldOffset(0)] internal int x0;
    [FieldOffset(4)] internal int x1;
    [FieldOffset(8)] internal int x2;
    [FieldOffset(12)] internal int x3;
    [FieldOffset(16)] internal int x4;
    [FieldOffset(20)] internal int x5;
    [FieldOffset(24)] internal int x6;
    [FieldOffset(28)] internal int x7;
    [FieldOffset(32)] internal int x8;
    [FieldOffset(36)] internal int x9;

    /// <summary>
    /// Creates a FieldElement from individual limb values.
    /// </summary>
    internal FieldElement(int x0, int x1, int x2, int x3, int x4,
                          int x5, int x6, int x7, int x8, int x9)
    {
        this.x0 = x0;
        this.x1 = x1;
        this.x2 = x2;
        this.x3 = x3;
        this.x4 = x4;
        this.x5 = x5;
        this.x6 = x6;
        this.x7 = x7;
        this.x8 = x8;
        this.x9 = x9;
    }

    /// <summary>
    /// Returns true if this field element is zero.
    /// Note: Due to the representation, multiple representations of zero exist.
    /// This checks if the element is in canonical form and equal to zero.
    /// </summary>
    internal bool IsNonZero()
    {
        var bytes = new byte[32];
        FieldOperations.fe_tobytes(bytes, 0, ref this);

        // Check if all bytes are zero
        var result = 0;
        for (int i = 0; i < 32; i++)
        {
            result |= bytes[i];
        }
        return result != 0;
    }

    /// <summary>
    /// Returns true if this field element is negative (odd).
    /// In Ed25519, a field element is considered negative if its least significant bit is 1.
    /// </summary>
    internal bool IsNegative()
    {
        var bytes = new byte[32];
        FieldOperations.fe_tobytes(bytes, 0, ref this);
        return (bytes[0] & 1) != 0;
    }
}
