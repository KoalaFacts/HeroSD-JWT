// Ported from Chaos.NaCl (https://github.com/CodesInChaos/Chaos.NaCl)
// Original Author: Dan Bernstein (djb) - Ref10 from SUPERCOP
// C# Port: Christian Winnerlein (CodesInChaos)
// License: Public Domain
//
// Group operations on Ed25519 curve points

using System;

namespace HeroSdJwt.Internal.Ed25519;

internal static partial class GroupOperations
{
    /// <summary>
    /// Converts a P1xP1 point to P2 projective coordinates.
    ///
    /// r.X = p.X * p.T
    /// r.Y = p.Y * p.Z
    /// r.Z = p.Z * p.T
    /// </summary>
    internal static void ge_p1p1_to_p2(out GroupElementP2 r, ref GroupElementP1P1 p)
    {
        FieldOperations.fe_mul(out r.X, ref p.X, ref p.T);
        FieldOperations.fe_mul(out r.Y, ref p.Y, ref p.Z);
        FieldOperations.fe_mul(out r.Z, ref p.Z, ref p.T);
    }

    /// <summary>
    /// Converts a P1xP1 point to P3 extended coordinates.
    ///
    /// r.X = p.X * p.T
    /// r.Y = p.Y * p.Z
    /// r.Z = p.Z * p.T
    /// r.T = p.X * p.Y
    /// </summary>
    internal static void ge_p1p1_to_p3(out GroupElementP3 r, ref GroupElementP1P1 p)
    {
        FieldOperations.fe_mul(out r.X, ref p.X, ref p.T);
        FieldOperations.fe_mul(out r.Y, ref p.Y, ref p.Z);
        FieldOperations.fe_mul(out r.Z, ref p.Z, ref p.T);
        FieldOperations.fe_mul(out r.T, ref p.X, ref p.Y);
    }

    /// <summary>
    /// Converts a P2 point to P3 extended coordinates.
    ///
    /// r.X = p.X
    /// r.Y = p.Y
    /// r.Z = p.Z
    /// r.T = p.X * p.Y
    /// </summary>
    internal static void ge_p2_to_p3(out GroupElementP3 r, ref GroupElementP2 p)
    {
        FieldOperations.fe_copy(out r.X, ref p.X);
        FieldOperations.fe_copy(out r.Y, ref p.Y);
        FieldOperations.fe_copy(out r.Z, ref p.Z);
        FieldOperations.fe_mul(out r.T, ref p.X, ref p.Y);
    }

    /// <summary>
    /// Converts a P3 point to cached form for efficient addition.
    ///
    /// r.YplusX = p.Y + p.X
    /// r.YminusX = p.Y - p.X
    /// r.Z = p.Z
    /// r.T2d = p.T * 2d (where d is the curve constant)
    /// </summary>
    internal static void ge_p3_to_cached(out GroupElementCached r, ref GroupElementP3 p)
    {
        FieldOperations.fe_add(out r.YplusX, ref p.Y, ref p.X);
        FieldOperations.fe_sub(out r.YminusX, ref p.Y, ref p.X);
        FieldOperations.fe_copy(out r.Z, ref p.Z);
        var d2 = LookupTables.d2;
        FieldOperations.fe_mul(out r.T2d, ref p.T, ref d2);
    }

    /// <summary>
    /// Converts a P3 point to P2 projective coordinates.
    ///
    /// r.X = p.X
    /// r.Y = p.Y
    /// r.Z = p.Z
    /// </summary>
    internal static void ge_p3_to_p2(out GroupElementP2 r, ref GroupElementP3 p)
    {
        FieldOperations.fe_copy(out r.X, ref p.X);
        FieldOperations.fe_copy(out r.Y, ref p.Y);
        FieldOperations.fe_copy(out r.Z, ref p.Z);
    }

    /// <summary>
    /// Sets r to the identity element (neutral point) of the curve.
    ///
    /// The identity element in extended coordinates is (0:1:1:0).
    /// </summary>
    internal static void ge_p3_0(out GroupElementP3 h)
    {
        FieldOperations.fe_0(out h.X);
        FieldOperations.fe_1(out h.Y);
        FieldOperations.fe_1(out h.Z);
        FieldOperations.fe_0(out h.T);
    }

    /// <summary>
    /// Sets r to the identity element in P2 form.
    ///
    /// The identity element in projective coordinates is (0:1:1).
    /// </summary>
    internal static void ge_p2_0(out GroupElementP2 h)
    {
        FieldOperations.fe_0(out h.X);
        FieldOperations.fe_1(out h.Y);
        FieldOperations.fe_1(out h.Z);
    }

    /// <summary>
    /// Sets a precomputed group element to the identity/neutral element.
    /// </summary>
    internal static void ge_precomp_0(out GroupElementPreComp h)
    {
        FieldOperations.fe_1(out h.yplusx);
        FieldOperations.fe_1(out h.yminusx);
        FieldOperations.fe_0(out h.xy2d);
    }

    /// <summary>
    /// Conditionally moves q to p based on bit b.
    /// If b == 1, p = q; if b == 0, p remains unchanged.
    /// Constant-time operation to prevent timing attacks.
    /// </summary>
    internal static void ge_cmov(ref GroupElementPreComp p, ref GroupElementPreComp q, int b)
    {
        FieldOperations.fe_cmov(ref p.yplusx, ref q.yplusx, b);
        FieldOperations.fe_cmov(ref p.yminusx, ref q.yminusx, b);
        FieldOperations.fe_cmov(ref p.xy2d, ref q.xy2d, b);
    }

    /// <summary>
    /// Conditionally negates a precomputed element based on bit b.
    /// If b == 1, negate; if b == 0, leave unchanged.
    /// Constant-time operation to prevent timing attacks.
    /// </summary>
    internal static void ge_precomp_cmov(ref GroupElementPreComp t, ref GroupElementPreComp u, byte b)
    {
        FieldOperations.fe_cmov(ref t.yplusx, ref u.yplusx, b);
        FieldOperations.fe_cmov(ref t.yminusx, ref u.yminusx, b);
        FieldOperations.fe_cmov(ref t.xy2d, ref u.xy2d, b);
    }
}
