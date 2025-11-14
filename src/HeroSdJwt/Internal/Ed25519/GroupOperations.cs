// Ported from Chaos.NaCl (https://github.com/CodesInChaos/Chaos.NaCl)
// Original Author: Dan Bernstein (djb) - Ref10 from SUPERCOP
// C# Port: Christian Winnerlein (CodesInChaos)
// License: Public Domain
//
// Group operations on Ed25519 curve points

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
    internal static void GeP1P1ToP2(out GroupElementP2 r, ref GroupElementP1P1 p)
    {
        FieldOperations.FeMul(out r.X, ref p.X, ref p.T);
        FieldOperations.FeMul(out r.Y, ref p.Y, ref p.Z);
        FieldOperations.FeMul(out r.Z, ref p.Z, ref p.T);
    }

    /// <summary>
    /// Converts a P1xP1 point to P3 extended coordinates.
    ///
    /// r.X = p.X * p.T
    /// r.Y = p.Y * p.Z
    /// r.Z = p.Z * p.T
    /// r.T = p.X * p.Y
    /// </summary>
    internal static void GeP1P1ToP3(out GroupElementP3 r, ref GroupElementP1P1 p)
    {
        FieldOperations.FeMul(out r.X, ref p.X, ref p.T);
        FieldOperations.FeMul(out r.Y, ref p.Y, ref p.Z);
        FieldOperations.FeMul(out r.Z, ref p.Z, ref p.T);
        FieldOperations.FeMul(out r.T, ref p.X, ref p.Y);
    }

    /// <summary>
    /// Converts a P2 point to P3 extended coordinates.
    ///
    /// r.X = p.X
    /// r.Y = p.Y
    /// r.Z = p.Z
    /// r.T = p.X * p.Y
    /// </summary>
    internal static void GeP2ToP3(out GroupElementP3 r, ref GroupElementP2 p)
    {
        FieldOperations.FeCopy(out r.X, ref p.X);
        FieldOperations.FeCopy(out r.Y, ref p.Y);
        FieldOperations.FeCopy(out r.Z, ref p.Z);
        FieldOperations.FeMul(out r.T, ref p.X, ref p.Y);
    }

    /// <summary>
    /// Converts a P3 point to cached form for efficient addition.
    ///
    /// r.YplusX = p.Y + p.X
    /// r.YminusX = p.Y - p.X
    /// r.Z = p.Z
    /// r.T2d = p.T * 2d (where d is the curve constant)
    /// </summary>
    internal static void GeP3ToCached(out GroupElementCached r, ref GroupElementP3 p)
    {
        FieldOperations.FeAdd(out r.YplusX, ref p.Y, ref p.X);
        FieldOperations.FeSub(out r.YminusX, ref p.Y, ref p.X);
        FieldOperations.FeCopy(out r.Z, ref p.Z);
        var d2 = LookupTables.d2;
        FieldOperations.FeMul(out r.T2d, ref p.T, ref d2);
    }

    /// <summary>
    /// Converts a P3 point to P2 projective coordinates.
    ///
    /// r.X = p.X
    /// r.Y = p.Y
    /// r.Z = p.Z
    /// </summary>
    internal static void GeP3ToP2(out GroupElementP2 r, ref GroupElementP3 p)
    {
        FieldOperations.FeCopy(out r.X, ref p.X);
        FieldOperations.FeCopy(out r.Y, ref p.Y);
        FieldOperations.FeCopy(out r.Z, ref p.Z);
    }

    /// <summary>
    /// Sets r to the identity element (neutral point) of the curve.
    ///
    /// The identity element in extended coordinates is (0:1:1:0).
    /// </summary>
    internal static void GeP3Zero(out GroupElementP3 h)
    {
        FieldOperations.FeZero(out h.X);
        FieldOperations.FeOne(out h.Y);
        FieldOperations.FeOne(out h.Z);
        FieldOperations.FeZero(out h.T);
    }

    /// <summary>
    /// Sets r to the identity element in P2 form.
    ///
    /// The identity element in projective coordinates is (0:1:1).
    /// </summary>
    internal static void GeP2Zero(out GroupElementP2 h)
    {
        FieldOperations.FeZero(out h.X);
        FieldOperations.FeOne(out h.Y);
        FieldOperations.FeOne(out h.Z);
    }

    /// <summary>
    /// Sets a precomputed group element to the identity/neutral element.
    /// </summary>
    internal static void GePrecompZero(out GroupElementPreComp h)
    {
        FieldOperations.FeOne(out h.yplusx);
        FieldOperations.FeOne(out h.yminusx);
        FieldOperations.FeZero(out h.xy2d);
    }

    /// <summary>
    /// Conditionally moves q to p based on bit b.
    /// If b == 1, p = q; if b == 0, p remains unchanged.
    /// Constant-time operation to prevent timing attacks.
    /// </summary>
    internal static void GeCmov(ref GroupElementPreComp p, ref GroupElementPreComp q, int b)
    {
        FieldOperations.FeCmov(ref p.yplusx, ref q.yplusx, b);
        FieldOperations.FeCmov(ref p.yminusx, ref q.yminusx, b);
        FieldOperations.FeCmov(ref p.xy2d, ref q.xy2d, b);
    }

    /// <summary>
    /// Conditionally negates a precomputed element based on bit b.
    /// If b == 1, negate; if b == 0, leave unchanged.
    /// Constant-time operation to prevent timing attacks.
    /// </summary>
    internal static void GePrecompCmov(ref GroupElementPreComp t, ref GroupElementPreComp u, byte b)
    {
        FieldOperations.FeCmov(ref t.yplusx, ref u.yplusx, b);
        FieldOperations.FeCmov(ref t.yminusx, ref u.yminusx, b);
        FieldOperations.FeCmov(ref t.xy2d, ref u.xy2d, b);
    }
}
