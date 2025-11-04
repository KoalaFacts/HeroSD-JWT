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
        56195235, 13857412, 51736253, 6949390, 114729,
        24766616, 60832955, 30306712, 48412415, 21499315
    );

    /// <summary>
    /// 2*d where d is the Ed25519 curve constant.
    ///
    /// Precomputed for efficiency in point operations.
    /// Used in converting P3 to Cached form.
    /// </summary>
    internal static readonly FieldElement d2 = new FieldElement(
        45281625, 27714825, 36363642, 13898781, 229458,
        15978800, 54557047, 27058993, 29715967, 9444199
    );

    /// <summary>
    /// sqrt(-1) in GF(2^255-19).
    ///
    /// Used for point decompression (recovering x from y).
    /// Value: 2^((p-1)/4) mod p where p = 2^255-19
    /// </summary>
    internal static readonly FieldElement sqrtm1 = new FieldElement(
        34513072, 25610706, 9377949, 3500415, 12389472,
        33281959, 41962654, 31548777, 326685, 11406482
    );

    /// <summary>
    /// Ed25519 base point B in extended coordinates (X:Y:Z:T).
    /// This is the standard generator point from RFC 8032.
    /// B has y-coordinate = 4/5 mod p and positive x-coordinate.
    /// </summary>
    internal static GroupElementP3 GetBasePoint()
    {
        return new GroupElementP3
        {
            X = new FieldElement(
                -14297830, -7645148, 16144683, -16471763, 27570974,
                -2696100, -26142465, 8378389, 20764389, 8758491
            ),
            Y = new FieldElement(
                -26843541, -6710886, 13421773, -13421773, 26843546,
                6710886, -13421773, 13421773, -26843546, -6710886
            ),
            Z = new FieldElement(
                1, 0, 0, 0, 0,
                0, 0, 0, 0, 0
            ),
            T = new FieldElement(
                28827062, -6116119, -27349572, 244363, 8635006,
                11264893, 19351346, 13413597, 16611511, -6414980
            )
        };
    }
}
