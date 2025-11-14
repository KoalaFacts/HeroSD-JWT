// Ported from Chaos.NaCl (https://github.com/CodesInChaos/Chaos.NaCl)
// Original Author: Dan Bernstein (djb) - Ref10 from SUPERCOP
// C# Port: Christian Winnerlein (CodesInChaos)
// License: Public Domain
//
// Point doubling operations for Ed25519

namespace HeroSdJwt.Internal.Ed25519;

internal static partial class GroupOperations
{
    /// <summary>
    /// Point doubling: r = 2*p
    ///
    /// Input: p in P2 form
    /// Output: r in P1xP1 form
    ///
    /// Uses the doubling formula for Edwards curves in projective coordinates.
    /// This is more efficient than adding a point to itself.
    /// </summary>
    internal static void GeP2Dbl(out GroupElementP1P1 r, ref GroupElementP2 p)
    {
        FieldElement t0;

        // XX = X1^2
        FieldOperations.FeSq(out r.X, ref p.X);

        // YY = Y1^2
        FieldOperations.FeSq(out r.Z, ref p.Y);

        // B = 2*Z1^2
        FieldOperations.FeSq2(out r.T, ref p.Z);

        // A = X1+Y1
        FieldOperations.FeAdd(out r.Y, ref p.X, ref p.Y);

        // AA = A^2
        FieldOperations.FeSq(out t0, ref r.Y);

        // Y3 = YY+XX
        FieldOperations.FeAdd(out r.Y, ref r.Z, ref r.X);

        // Z3 = YY-XX
        FieldOperations.FeSub(out r.Z, ref r.Z, ref r.X);

        // X3 = AA-Y3
        FieldOperations.FeSub(out r.X, ref t0, ref r.Y);

        // T3 = B-Z3
        FieldOperations.FeSub(out r.T, ref r.T, ref r.Z);
    }

    /// <summary>
    /// Point doubling: r = 2*p
    ///
    /// Input: p in P3 form
    /// Output: r in P1xP1 form
    ///
    /// More efficient doubling for points in extended coordinates.
    /// Converts to P2 and then doubles.
    /// </summary>
    internal static void GeP3Dbl(out GroupElementP1P1 r, ref GroupElementP3 p)
    {
        GroupElementP2 q;
        GeP3ToP2(out q, ref p);
        GeP2Dbl(out r, ref q);
    }
}
