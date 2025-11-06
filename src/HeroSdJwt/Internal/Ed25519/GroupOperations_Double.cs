// Ported from Chaos.NaCl (https://github.com/CodesInChaos/Chaos.NaCl)
// Original Author: Dan Bernstein (djb) - Ref10 from SUPERCOP
// C# Port: Christian Winnerlein (CodesInChaos)
// License: Public Domain
//
// Point doubling operations for Ed25519

using System;

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
    internal static void ge_p2_dbl(out GroupElementP1P1 r, ref GroupElementP2 p)
    {
        FieldElement t0;

        // XX = X1^2
        FieldOperations.fe_sq(out r.X, ref p.X);

        // YY = Y1^2
        FieldOperations.fe_sq(out r.Z, ref p.Y);

        // B = 2*Z1^2
        FieldOperations.fe_sq2(out r.T, ref p.Z);

        // A = X1+Y1
        FieldOperations.fe_add(out r.Y, ref p.X, ref p.Y);

        // AA = A^2
        FieldOperations.fe_sq(out t0, ref r.Y);

        // Y3 = YY+XX
        FieldOperations.fe_add(out r.Y, ref r.Z, ref r.X);

        // Z3 = YY-XX
        FieldOperations.fe_sub(out r.Z, ref r.Z, ref r.X);

        // X3 = AA-Y3
        FieldOperations.fe_sub(out r.X, ref t0, ref r.Y);

        // T3 = B-Z3
        FieldOperations.fe_sub(out r.T, ref r.T, ref r.Z);
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
    internal static void ge_p3_dbl(out GroupElementP1P1 r, ref GroupElementP3 p)
    {
        GroupElementP2 q;
        ge_p3_to_p2(out q, ref p);
        ge_p2_dbl(out r, ref q);
    }
}
