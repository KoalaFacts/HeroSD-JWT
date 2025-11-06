// Ported from Chaos.NaCl (https://github.com/CodesInChaos/Chaos.NaCl)
// Original Author: Dan Bernstein (djb) - Ref10 from SUPERCOP
// C# Port: Christian Winnerlein (CodesInChaos)
// License: Public Domain
//
// Point addition operations for Ed25519

using System;

namespace HeroSdJwt.Internal.Ed25519;

internal static partial class GroupOperations
{
    /// <summary>
    /// Adds two points: r = p + q
    ///
    /// Input: p in P3 form, q in Cached form
    /// Output: r in P1xP1 form
    ///
    /// Uses the unified addition formula for Edwards curves.
    /// </summary>
    internal static void ge_add(out GroupElementP1P1 r, ref GroupElementP3 p, ref GroupElementCached q)
    {
        FieldElement t0;

        // A = (Y1-X1)*(Y2-X2)
        FieldOperations.fe_add(out r.X, ref p.Y, ref p.X);
        FieldOperations.fe_sub(out r.Y, ref p.Y, ref p.X);
        FieldOperations.fe_mul(out r.Z, ref r.X, ref q.YplusX);
        FieldOperations.fe_mul(out r.Y, ref r.Y, ref q.YminusX);

        // B = (Y1+X1)*(Y2+X2)
        FieldOperations.fe_mul(out r.T, ref q.T2d, ref p.T);

        // C = T1*2d*T2
        FieldOperations.fe_mul(out r.X, ref p.Z, ref q.Z);

        // D = Z1*Z2
        FieldOperations.fe_add(out t0, ref r.X, ref r.X);

        // E = B-A
        FieldOperations.fe_sub(out r.X, ref r.Z, ref r.Y);

        // F = D-C
        FieldOperations.fe_add(out r.Y, ref r.Z, ref r.Y);

        // G = D+C
        FieldOperations.fe_add(out r.Z, ref t0, ref r.T);

        // H = B+A
        FieldOperations.fe_sub(out r.T, ref t0, ref r.T);

        // X3 = E*F
        // Y3 = G*H
        // Z3 = F*G
        // T3 = E*H
    }

    /// <summary>
    /// Subtracts two points: r = p - q
    ///
    /// Input: p in P3 form, q in Cached form
    /// Output: r in P1xP1 form
    ///
    /// Equivalent to adding p + (-q).
    /// </summary>
    internal static void ge_sub(out GroupElementP1P1 r, ref GroupElementP3 p, ref GroupElementCached q)
    {
        FieldElement t0;

        FieldOperations.fe_add(out r.X, ref p.Y, ref p.X);
        FieldOperations.fe_sub(out r.Y, ref p.Y, ref p.X);

        // Note: YplusX and YminusX are swapped compared to ge_add
        FieldOperations.fe_mul(out r.Z, ref r.X, ref q.YminusX);
        FieldOperations.fe_mul(out r.Y, ref r.Y, ref q.YplusX);
        FieldOperations.fe_mul(out r.T, ref q.T2d, ref p.T);
        FieldOperations.fe_mul(out r.X, ref p.Z, ref q.Z);

        FieldOperations.fe_add(out t0, ref r.X, ref r.X);

        FieldOperations.fe_sub(out r.X, ref r.Z, ref r.Y);
        FieldOperations.fe_add(out r.Y, ref r.Z, ref r.Y);

        // Note: Subtraction instead of addition (compared to ge_add)
        FieldOperations.fe_sub(out r.Z, ref t0, ref r.T);
        FieldOperations.fe_add(out r.T, ref t0, ref r.T);
    }

    /// <summary>
    /// Mixed addition: r = p + q
    ///
    /// Input: p in P3 form, q in PreComp form (affine-like coordinates)
    /// Output: r in P1xP1 form
    ///
    /// More efficient than ge_add when q is in PreComp form.
    /// Used during scalar multiplication with precomputed tables.
    /// </summary>
    internal static void ge_madd(out GroupElementP1P1 r, ref GroupElementP3 p, ref GroupElementPreComp q)
    {
        FieldElement t0;

        FieldOperations.fe_add(out r.X, ref p.Y, ref p.X);
        FieldOperations.fe_sub(out r.Y, ref p.Y, ref p.X);
        FieldOperations.fe_mul(out r.Z, ref r.X, ref q.yplusx);
        FieldOperations.fe_mul(out r.Y, ref r.Y, ref q.yminusx);
        FieldOperations.fe_mul(out r.T, ref q.xy2d, ref p.T);

        FieldOperations.fe_add(out t0, ref p.Z, ref p.Z);

        FieldOperations.fe_sub(out r.X, ref r.Z, ref r.Y);
        FieldOperations.fe_add(out r.Y, ref r.Z, ref r.Y);
        FieldOperations.fe_add(out r.Z, ref t0, ref r.T);
        FieldOperations.fe_sub(out r.T, ref t0, ref r.T);
    }

    /// <summary>
    /// Mixed subtraction: r = p - q
    ///
    /// Input: p in P3 form, q in PreComp form
    /// Output: r in P1xP1 form
    ///
    /// More efficient than ge_sub when q is in PreComp form.
    /// </summary>
    internal static void ge_msub(out GroupElementP1P1 r, ref GroupElementP3 p, ref GroupElementPreComp q)
    {
        FieldElement t0;

        FieldOperations.fe_add(out r.X, ref p.Y, ref p.X);
        FieldOperations.fe_sub(out r.Y, ref p.Y, ref p.X);

        // Note: yplusx and yminusx are swapped compared to ge_madd
        FieldOperations.fe_mul(out r.Z, ref r.X, ref q.yminusx);
        FieldOperations.fe_mul(out r.Y, ref r.Y, ref q.yplusx);
        FieldOperations.fe_mul(out r.T, ref q.xy2d, ref p.T);

        FieldOperations.fe_add(out t0, ref p.Z, ref p.Z);

        FieldOperations.fe_sub(out r.X, ref r.Z, ref r.Y);
        FieldOperations.fe_add(out r.Y, ref r.Z, ref r.Y);

        // Note: Subtraction instead of addition (compared to ge_madd)
        FieldOperations.fe_sub(out r.Z, ref t0, ref r.T);
        FieldOperations.fe_add(out r.T, ref t0, ref r.T);
    }
}
