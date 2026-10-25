using System.Security.Cryptography;

namespace HeroSdJwt.Cryptography;

// ES256 is defined on the named NIST P-256 curve, not on every 256-bit curve.
// Comparing OIDs also prevents secp256k1 keys from being relabelled as P-256 JWKs.
internal static class EcCurveGuard
{
    internal static bool IsP256(ECDsa key)
    {
        try
        {
            return key.KeySize == 256 &&
                string.Equals(key.ExportParameters(false).Curve.Oid.Value,
                    ECCurve.NamedCurves.nistP256.Oid.Value, StringComparison.Ordinal);
        }
        catch (CryptographicException)
        {
            return false;
        }
        catch (NotSupportedException)
        {
            return false;
        }
    }
}
