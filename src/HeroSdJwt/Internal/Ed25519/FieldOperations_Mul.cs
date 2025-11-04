// Ported from Chaos.NaCl (https://github.com/CodesInChaos/Chaos.NaCl)
// Original Author: Dan Bernstein (djb) - Ref10 from SUPERCOP
// C# Port: Christian Winnerlein (CodesInChaos)
// License: Public Domain
//
// Complex field operations: multiplication, squaring, and serialization

using System;

namespace HeroSdJwt.Internal.Ed25519;

/// <summary>
/// Field arithmetic operations - complex operations part.
/// </summary>
internal static partial class FieldOperations
{
    /// <summary>
    /// h = f * g
    ///
    /// Computes the product of two field elements.
    /// Can overlap h with f or g.
    ///
    /// Preconditions:
    ///   |f| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.
    ///   |g| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.
    ///
    /// Postconditions:
    ///   |h| bounded by 1.01*2^25,1.01*2^24,1.01*2^25,1.01*2^24,etc.
    /// </summary>
    internal static void fe_mul(out FieldElement h, ref FieldElement f, ref FieldElement g)
    {
        int f0 = f.x0, f1 = f.x1, f2 = f.x2, f3 = f.x3, f4 = f.x4;
        int f5 = f.x5, f6 = f.x6, f7 = f.x7, f8 = f.x8, f9 = f.x9;
        int g0 = g.x0, g1 = g.x1, g2 = g.x2, g3 = g.x3, g4 = g.x4;
        int g5 = g.x5, g6 = g.x6, g7 = g.x7, g8 = g.x8, g9 = g.x9;

        int g1_19 = 19 * g1; /* 1.959375*2^29 */
        int g2_19 = 19 * g2; /* 1.959375*2^30; still ok */
        int g3_19 = 19 * g3;
        int g4_19 = 19 * g4;
        int g5_19 = 19 * g5;
        int g6_19 = 19 * g6;
        int g7_19 = 19 * g7;
        int g8_19 = 19 * g8;
        int g9_19 = 19 * g9;
        int f1_2 = 2 * f1;
        int f3_2 = 2 * f3;
        int f5_2 = 2 * f5;
        int f7_2 = 2 * f7;
        int f9_2 = 2 * f9;

        long f0g0 = f0 * (long)g0;
        long f0g1 = f0 * (long)g1;
        long f0g2 = f0 * (long)g2;
        long f0g3 = f0 * (long)g3;
        long f0g4 = f0 * (long)g4;
        long f0g5 = f0 * (long)g5;
        long f0g6 = f0 * (long)g6;
        long f0g7 = f0 * (long)g7;
        long f0g8 = f0 * (long)g8;
        long f0g9 = f0 * (long)g9;
        long f1g0 = f1 * (long)g0;
        long f1g1_2 = f1_2 * (long)g1;
        long f1g2 = f1 * (long)g2;
        long f1g3_2 = f1_2 * (long)g3;
        long f1g4 = f1 * (long)g4;
        long f1g5_2 = f1_2 * (long)g5;
        long f1g6 = f1 * (long)g6;
        long f1g7_2 = f1_2 * (long)g7;
        long f1g8 = f1 * (long)g8;
        long f1g9_38 = f1_2 * (long)g9_19;
        long f2g0 = f2 * (long)g0;
        long f2g1 = f2 * (long)g1;
        long f2g2 = f2 * (long)g2;
        long f2g3 = f2 * (long)g3;
        long f2g4 = f2 * (long)g4;
        long f2g5 = f2 * (long)g5;
        long f2g6 = f2 * (long)g6;
        long f2g7 = f2 * (long)g7;
        long f2g8_19 = f2 * (long)g8_19;
        long f2g9_19 = f2 * (long)g9_19;
        long f3g0 = f3 * (long)g0;
        long f3g1_2 = f3_2 * (long)g1;
        long f3g2 = f3 * (long)g2;
        long f3g3_2 = f3_2 * (long)g3;
        long f3g4 = f3 * (long)g4;
        long f3g5_2 = f3_2 * (long)g5;
        long f3g6 = f3 * (long)g6;
        long f3g7_38 = f3_2 * (long)g7_19;
        long f3g8_19 = f3 * (long)g8_19;
        long f3g9_38 = f3_2 * (long)g9_19;
        long f4g0 = f4 * (long)g0;
        long f4g1 = f4 * (long)g1;
        long f4g2 = f4 * (long)g2;
        long f4g3 = f4 * (long)g3;
        long f4g4 = f4 * (long)g4;
        long f4g5 = f4 * (long)g5;
        long f4g6_19 = f4 * (long)g6_19;
        long f4g7_19 = f4 * (long)g7_19;
        long f4g8_19 = f4 * (long)g8_19;
        long f4g9_19 = f4 * (long)g9_19;
        long f5g0 = f5 * (long)g0;
        long f5g1_2 = f5_2 * (long)g1;
        long f5g2 = f5 * (long)g2;
        long f5g3_2 = f5_2 * (long)g3;
        long f5g4 = f5 * (long)g4;
        long f5g5_38 = f5_2 * (long)g5_19;
        long f5g6_19 = f5 * (long)g6_19;
        long f5g7_38 = f5_2 * (long)g7_19;
        long f5g8_19 = f5 * (long)g8_19;
        long f5g9_38 = f5_2 * (long)g9_19;
        long f6g0 = f6 * (long)g0;
        long f6g1 = f6 * (long)g1;
        long f6g2 = f6 * (long)g2;
        long f6g3 = f6 * (long)g3;
        long f6g4_19 = f6 * (long)g4_19;
        long f6g5_19 = f6 * (long)g5_19;
        long f6g6_19 = f6 * (long)g6_19;
        long f6g7_19 = f6 * (long)g7_19;
        long f6g8_19 = f6 * (long)g8_19;
        long f6g9_19 = f6 * (long)g9_19;
        long f7g0 = f7 * (long)g0;
        long f7g1_2 = f7_2 * (long)g1;
        long f7g2 = f7 * (long)g2;
        long f7g3_38 = f7_2 * (long)g3_19;
        long f7g4_19 = f7 * (long)g4_19;
        long f7g5_38 = f7_2 * (long)g5_19;
        long f7g6_19 = f7 * (long)g6_19;
        long f7g7_38 = f7_2 * (long)g7_19;
        long f7g8_19 = f7 * (long)g8_19;
        long f7g9_38 = f7_2 * (long)g9_19;
        long f8g0 = f8 * (long)g0;
        long f8g1 = f8 * (long)g1;
        long f8g2_19 = f8 * (long)g2_19;
        long f8g3_19 = f8 * (long)g3_19;
        long f8g4_19 = f8 * (long)g4_19;
        long f8g5_19 = f8 * (long)g5_19;
        long f8g6_19 = f8 * (long)g6_19;
        long f8g7_19 = f8 * (long)g7_19;
        long f8g8_19 = f8 * (long)g8_19;
        long f8g9_19 = f8 * (long)g9_19;
        long f9g0 = f9 * (long)g0;
        long f9g1_38 = f9_2 * (long)g1_19;
        long f9g2_19 = f9 * (long)g2_19;
        long f9g3_38 = f9_2 * (long)g3_19;
        long f9g4_19 = f9 * (long)g4_19;
        long f9g5_38 = f9_2 * (long)g5_19;
        long f9g6_19 = f9 * (long)g6_19;
        long f9g7_38 = f9_2 * (long)g7_19;
        long f9g8_19 = f9 * (long)g8_19;
        long f9g9_38 = f9_2 * (long)g9_19;

        long h0 = f0g0 + f1g9_38 + f2g8_19 + f3g7_38 + f4g6_19 + f5g5_38 + f6g4_19 + f7g3_38 + f8g2_19 + f9g1_38;
        long h1 = f0g1 + f1g0 + f2g9_19 + f3g8_19 + f4g7_19 + f5g6_19 + f6g5_19 + f7g4_19 + f8g3_19 + f9g2_19;
        long h2 = f0g2 + f1g1_2 + f2g0 + f3g9_38 + f4g8_19 + f5g7_38 + f6g6_19 + f7g5_38 + f8g4_19 + f9g3_38;
        long h3 = f0g3 + f1g2 + f2g1 + f3g0 + f4g9_19 + f5g8_19 + f6g7_19 + f7g6_19 + f8g5_19 + f9g4_19;
        long h4 = f0g4 + f1g3_2 + f2g2 + f3g1_2 + f4g0 + f5g9_38 + f6g8_19 + f7g7_38 + f8g6_19 + f9g5_38;
        long h5 = f0g5 + f1g4 + f2g3 + f3g2 + f4g1 + f5g0 + f6g9_19 + f7g8_19 + f8g7_19 + f9g6_19;
        long h6 = f0g6 + f1g5_2 + f2g4 + f3g3_2 + f4g2 + f5g1_2 + f6g0 + f7g9_38 + f8g8_19 + f9g7_38;
        long h7 = f0g7 + f1g6 + f2g5 + f3g4 + f4g3 + f5g2 + f6g1 + f7g0 + f8g9_19 + f9g8_19;
        long h8 = f0g8 + f1g7_2 + f2g6 + f3g5_2 + f4g4 + f5g3_2 + f6g2 + f7g1_2 + f8g0 + f9g9_38;
        long h9 = f0g9 + f1g8 + f2g7 + f3g6 + f4g5 + f5g4 + f6g3 + f7g2 + f8g1 + f9g0;

        long carry0, carry1, carry2, carry3, carry4, carry5, carry6, carry7, carry8, carry9;

        carry0 = (h0 + (1 << 25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
        carry4 = (h4 + (1 << 25)) >> 26; h5 += carry4; h4 -= carry4 << 26;

        carry1 = (h1 + (1 << 24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
        carry5 = (h5 + (1 << 24)) >> 25; h6 += carry5; h5 -= carry5 << 25;

        carry2 = (h2 + (1 << 25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
        carry6 = (h6 + (1 << 25)) >> 26; h7 += carry6; h6 -= carry6 << 26;

        carry3 = (h3 + (1 << 24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
        carry7 = (h7 + (1 << 24)) >> 25; h8 += carry7; h7 -= carry7 << 25;

        carry4 = (h4 + (1 << 25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
        carry8 = (h8 + (1 << 25)) >> 26; h9 += carry8; h8 -= carry8 << 26;

        carry9 = (h9 + (1 << 24)) >> 25; h0 += carry9 * 19; h9 -= carry9 << 25;

        carry0 = (h0 + (1 << 25)) >> 26; h1 += carry0; h0 -= carry0 << 26;

        h.x0 = (int)h0;
        h.x1 = (int)h1;
        h.x2 = (int)h2;
        h.x3 = (int)h3;
        h.x4 = (int)h4;
        h.x5 = (int)h5;
        h.x6 = (int)h6;
        h.x7 = (int)h7;
        h.x8 = (int)h8;
        h.x9 = (int)h9;
    }
}
