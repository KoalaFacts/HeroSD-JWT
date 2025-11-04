// Ported from Chaos.NaCl (https://github.com/CodesInChaos/Chaos.NaCl)
// Original Author: Dan Bernstein (djb) - Ref10 from SUPERCOP
// C# Port: Christian Winnerlein (CodesInChaos)
// License: Public Domain
//
// Curve constants and precomputed tables for Ed25519

using System;

namespace HeroSdJwt.Internal.Ed25519;

internal static partial class LookupTables
{
    /// <summary>
    /// Ed25519 curve constant d = -121665/121666 in GF(2^255-19).
    ///
    /// The Ed25519 curve equation is: -x^2 + y^2 = 1 + d*x^2*y^2
    ///
    /// Value: 37095705934669439343138083508754565189542113879843219016388785533085940283555
    /// </summary>
    internal static readonly FieldElement d = new FieldElement(
        -10913610, 13857413, -15372611, 6949391, 114729,
        -8787816, -6275908, -3247719, -18696448, -12055116
    );

    /// <summary>
    /// 2*d where d is the Ed25519 curve constant.
    ///
    /// Precomputed for efficiency in point operations.
    /// Used in converting P3 to Cached form.
    /// </summary>
    internal static readonly FieldElement d2 = new FieldElement(
        -21827239, -5839606, -30745221, 13898782, 229458,
        15978800, -12551817, -6495438, 29715968, 9444199
    );

    /// <summary>
    /// sqrt(-1) in GF(2^255-19).
    ///
    /// Used for point decompression (recovering x from y).
    /// </summary>
    internal static readonly FieldElement sqrtm1 = new FieldElement(
        -32595792, -7943725, 9377950, 3500415, 12389472,
        -272473, -25146209, -2005654, 326686, 11406482
    );
}
