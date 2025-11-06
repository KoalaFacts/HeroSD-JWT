// Ported from Chaos.NaCl (https://github.com/CodesInChaos/Chaos.NaCl)
// Original Author: Dan Bernstein (djb) - Ref10 from SUPERCOP
// C# Port: Christian Winnerlein (CodesInChaos)
// License: Public Domain
//
// Group elements (points on the Ed25519 curve)
//
// Ed25519 curve equation: -x^2 + y^2 = 1 + d*x^2*y^2 where d = -121665/121666
//
// Points can be represented in different coordinate systems for efficiency:
// - P2: Projective (X:Y:Z) where x=X/Z, y=Y/Z
// - P3: Extended (X:Y:Z:T) where x=X/Z, y=Y/Z, T=XY/Z
// - P1xP1: Intermediate form for doubling
// - Cached: Precomputed values for addition
// - PreComp: Precomputed values for fixed-base multiplication

using System;
using System.Runtime.InteropServices;

namespace HeroSdJwt.Internal.Ed25519;

/// <summary>
/// Represents a point on the Ed25519 curve in projective coordinates (X:Y:Z).
///
/// Satisfies curve equation: -X^2 + Y^2 = Z^2 + d*X^2*Y^2
/// where x = X/Z, y = Y/Z
///
/// This representation avoids divisions during intermediate calculations.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct GroupElementP2
{
    internal FieldElement X;
    internal FieldElement Y;
    internal FieldElement Z;
}

/// <summary>
/// Represents a point on the Ed25519 curve in extended coordinates (X:Y:Z:T).
///
/// Satisfies curve equation: -X^2 + Y^2 = Z^2 + d*X^2*Y^2
/// where x = X/Z, y = Y/Z, T = XY/Z
///
/// The extra T coordinate allows for faster point addition.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct GroupElementP3
{
    internal FieldElement X;
    internal FieldElement Y;
    internal FieldElement Z;
    internal FieldElement T;
}

/// <summary>
/// Represents a point in intermediate coordinates (X:Y:Z:T).
///
/// Used as intermediate form during point doubling and addition operations.
/// Can be converted to P2 or P3 form.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct GroupElementP1P1
{
    internal FieldElement X;
    internal FieldElement Y;
    internal FieldElement Z;
    internal FieldElement T;
}

/// <summary>
/// Cached representation of a point for efficient addition.
///
/// Stores precomputed values (Y+X, Y-X, Z, 2d*T) that speed up
/// mixed addition operations.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct GroupElementCached
{
    internal FieldElement YplusX;
    internal FieldElement YminusX;
    internal FieldElement Z;
    internal FieldElement T2d;
}

/// <summary>
/// Precomputed representation for fixed-base scalar multiplication.
///
/// Stores precomputed values (y+x, y-x, 2d*xy) for a fixed point.
/// Used in precomputed tables for the base point.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct GroupElementPreComp
{
    internal FieldElement yplusx;
    internal FieldElement yminusx;
    internal FieldElement xy2d;

    internal GroupElementPreComp(FieldElement yplusx, FieldElement yminusx, FieldElement xy2d)
    {
        this.yplusx = yplusx;
        this.yminusx = yminusx;
        this.xy2d = xy2d;
    }
}
