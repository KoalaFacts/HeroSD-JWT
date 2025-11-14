// Ported from Chaos.NaCl (https://github.com/CodesInChaos/Chaos.NaCl)
// Original Author: Dan Bernstein (djb) - Ref10 from SUPERCOP
// C# Port: Christian Winnerlein (CodesInChaos)
// License: Public Domain
//
// Field element exponentiation

namespace HeroSdJwt.Internal.Ed25519;

internal static partial class FieldOperations
{
    /// <summary>
    /// Computes z = x^((p-5)/8) where p = 2^255-19.
    ///
    /// This is used for computing square roots in GF(2^255-19).
    /// The exponent (p-5)/8 = (2^255-24)/8 = 2^252-3.
    ///
    /// Uses addition chain for efficient exponentiation:
    /// - Minimize the number of multiplications needed
    /// - Use squaring operations when possible (cheaper than multiplication)
    /// </summary>
    internal static void FePow22523(out FieldElement output, ref FieldElement z)
    {
        FieldElement t0, t1, t2;

        // 2 == 2 * 1
        FeSq(out t0, ref z);

        // 4 == 2 * 2
        FeSq(out t1, ref t0);

        // 8 == 2 * 4
        FeSq(out t1, ref t1);

        // 9 == 8 + 1
        FeMul(out t1, ref z, ref t1);

        // 11 == 9 + 2
        FeMul(out t0, ref t0, ref t1);

        // 22 == 2 * 11
        FeSq(out t0, ref t0);

        // 31 == 22 + 9
        FeMul(out t0, ref t1, ref t0);

        // 2^6 - 2^1
        FeSq(out t1, ref t0);

        // 2^10 - 2^5
        for (int i = 1; i < 5; ++i)
        {
            FeSq(out t1, ref t1);
        }

        // 2^10 - 2^0
        FeMul(out t0, ref t1, ref t0);

        // 2^11 - 2^1
        FeSq(out t1, ref t0);

        // 2^20 - 2^10
        for (int i = 1; i < 10; ++i)
        {
            FeSq(out t1, ref t1);
        }

        // 2^20 - 2^0
        FeMul(out t1, ref t1, ref t0);

        // 2^21 - 2^1
        FeSq(out t2, ref t1);

        // 2^40 - 2^20
        for (int i = 1; i < 20; ++i)
        {
            FeSq(out t2, ref t2);
        }

        // 2^40 - 2^0
        FeMul(out t1, ref t2, ref t1);

        // 2^41 - 2^1
        FeSq(out t1, ref t1);

        // 2^50 - 2^10
        for (int i = 1; i < 10; ++i)
        {
            FeSq(out t1, ref t1);
        }

        // 2^50 - 2^0
        FeMul(out t0, ref t1, ref t0);

        // 2^51 - 2^1
        FeSq(out t1, ref t0);

        // 2^100 - 2^50
        for (int i = 1; i < 50; ++i)
        {
            FeSq(out t1, ref t1);
        }

        // 2^100 - 2^0
        FeMul(out t1, ref t1, ref t0);

        // 2^101 - 2^1
        FeSq(out t2, ref t1);

        // 2^200 - 2^100
        for (int i = 1; i < 100; ++i)
        {
            FeSq(out t2, ref t2);
        }

        // 2^200 - 2^0
        FeMul(out t1, ref t2, ref t1);

        // 2^201 - 2^1
        FeSq(out t1, ref t1);

        // 2^250 - 2^50
        for (int i = 1; i < 50; ++i)
        {
            FeSq(out t1, ref t1);
        }

        // 2^250 - 2^0
        FeMul(out t0, ref t1, ref t0);

        // 2^251 - 2^1
        FeSq(out t0, ref t0);

        // 2^252 - 2^2
        FeSq(out t0, ref t0);

        // 2^252 - 3
        FeMul(out output, ref t0, ref z);
    }
}
