// Ported from Chaos.NaCl (https://github.com/CodesInChaos/Chaos.NaCl)
// Original Author: Dan Bernstein (djb) - Ref10 from SUPERCOP
// C# Port: Christian Winnerlein (CodesInChaos)
// License: Public Domain
//
// Point encoding/decoding for Ed25519

using System;

namespace HeroSdJwt.Internal.Ed25519;

internal static partial class GroupOperations
{
    /// <summary>
    /// Encodes a group element to 32 bytes.
    ///
    /// The encoding format is:
    /// - Bytes 0-31: y-coordinate in little-endian
    /// - Bit 255 (top bit of byte 31): sign of x-coordinate
    ///
    /// This compressed format stores only the y-coordinate and the sign of x,
    /// which is sufficient to uniquely identify a point on the curve.
    /// </summary>
    internal static void GeToBytes(byte[] s, int offset, ref GroupElementP2 h)
    {
        FieldElement recip, x, y;

        // Compute 1/Z
        FieldOperations.FeInvert(out recip, ref h.Z);

        // Compute affine x = X/Z
        FieldOperations.FeMul(out x, ref h.X, ref recip);

        // Compute affine y = Y/Z
        FieldOperations.FeMul(out y, ref h.Y, ref recip);

        // Encode y-coordinate
        FieldOperations.FeToBytes(s, offset, ref y);

        // Set top bit to sign of x (x mod 2)
        s[offset + 31] ^= (byte)(x.IsNegative() ? 0x80 : 0);
    }

    /// <summary>
    /// Encodes a group element in P3 form to 32 bytes.
    /// </summary>
    internal static void GeP3ToBytes(byte[] s, int offset, ref GroupElementP3 h)
    {
        FieldElement recip, x, y;

        // Compute 1/Z
        FieldOperations.FeInvert(out recip, ref h.Z);

        // Compute affine x = X/Z
        FieldOperations.FeMul(out x, ref h.X, ref recip);

        // Compute affine y = Y/Z
        FieldOperations.FeMul(out y, ref h.Y, ref recip);

        // Encode y-coordinate
        FieldOperations.FeToBytes(s, offset, ref y);

        // Set top bit to sign of x (x mod 2)
        s[offset + 31] ^= (byte)(x.IsNegative() ? 0x80 : 0);
    }

    /// <summary>
    /// Decodes a group element from 32 bytes.
    ///
    /// Returns true if successful, false if the input doesn't represent a valid point.
    ///
    /// The decoding process:
    /// 1. Extract y-coordinate from bytes 0-31 (ignoring top bit)
    /// 2. Extract x sign from bit 255
    /// 3. Recover x-coordinate using curve equation: x^2 = (y^2-1)/(dy^2+1)
    /// 4. Adjust x sign to match the encoded sign bit
    /// </summary>
    internal static bool GeFromBytesNegateVartime(out GroupElementP3 h, byte[] s, int offset)
    {
        FieldElement u, v, v3, vxx, check;

        // Extract y-coordinate (ignore top bit)
        FieldOperations.FeFromBytes(out h.Y, s, offset);

        // Set Z = 1
        FieldOperations.FeOne(out h.Z);

        // Compute u = y^2
        FieldOperations.FeSq(out u, ref h.Y);

        // Compute v = dy^2
        var d = LookupTables.d;
        FieldOperations.FeMul(out v, ref u, ref d);

        // Compute u = y^2-1
        FieldOperations.FeSub(out u, ref u, ref h.Z);

        // Compute v = dy^2+1
        FieldOperations.FeAdd(out v, ref v, ref h.Z);

        // Compute v^3
        FieldOperations.FeSq(out v3, ref v);
        FieldOperations.FeMul(out v3, ref v3, ref v);

        // Compute v^6 = (v^3)^2
        FieldOperations.FeSq(out h.X, ref v3);

        // Compute v^7 = v^6 * v
        FieldOperations.FeMul(out h.X, ref h.X, ref v);

        // Compute uv^7
        FieldOperations.FeMul(out h.X, ref h.X, ref u);

        // Compute x = (uv^7)^((q-5)/8)
        FieldOperations.FePow22523(out h.X, ref h.X);

        // Multiply by uv^3
        FieldOperations.FeMul(out h.X, ref h.X, ref v3);
        FieldOperations.FeMul(out h.X, ref h.X, ref u);

        // Check if we got the right square root
        FieldOperations.FeSq(out vxx, ref h.X);
        FieldOperations.FeMul(out vxx, ref vxx, ref v);
        FieldOperations.FeSub(out check, ref vxx, ref u);

        if (!check.IsNonZero())
        {
            // x is correct
        }
        else
        {
            // Try x * sqrt(-1)
            FieldOperations.FeAdd(out check, ref vxx, ref u);
            if (!check.IsNonZero())
            {
                var sqrtm1 = LookupTables.sqrtm1;
                FieldOperations.FeMul(out h.X, ref h.X, ref sqrtm1);
            }
            else
            {
                // Point is not on curve
                h = default;
                return false;
            }
        }

        // Adjust sign of x
        bool x_is_negative = h.X.IsNegative();
        bool s_is_negative = (s[offset + 31] & 0x80) != 0;

        if (x_is_negative != s_is_negative)
        {
            FieldOperations.FeNeg(out h.X, ref h.X);
        }

        // Compute T = XY
        FieldOperations.FeMul(out h.T, ref h.X, ref h.Y);

        return true;
    }
}
