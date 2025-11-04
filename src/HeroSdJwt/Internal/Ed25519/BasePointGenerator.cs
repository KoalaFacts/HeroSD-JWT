// Generates the Ed25519 base point from the specification
// This is a one-time utility to compute the correct base point coordinates

using System;

namespace HeroSdJwt.Internal.Ed25519;

internal static class BasePointGenerator
{
    /// <summary>
    /// Computes the Ed25519 base point from its compressed form.
    /// The base point has y-coordinate = 4/5 mod p and positive x-coordinate.
    /// </summary>
    internal static GroupElementP3 ComputeBasePoint()
    {
        // RFC 8032: The base point has y = 4/5 mod p
        // In compressed form (little-endian): 0x5866666666666666666666666666666666666666666666666666666666666666
        byte[] basePointCompressed = new byte[32]
        {
            0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
        };

        // Decompress the base point
        GroupElementP3 basePoint;
        if (!GroupOperations.ge_frombytes_negate_vartime(out basePoint, basePointCompressed, 0))
        {
            throw new InvalidOperationException("Failed to decompress base point");
        }

        // ge_frombytes_negate_vartime negates the point, so negate it back
        FieldOperations.fe_neg(out basePoint.X, ref basePoint.X);
        FieldOperations.fe_neg(out basePoint.T, ref basePoint.T);

        return basePoint;
    }
}
