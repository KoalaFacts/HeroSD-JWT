using HeroSdJwt.Cryptography;
using HeroSdJwt.Encoding;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// A rejected JOSE ECDSA signature should not allocate a second ASN.1 signature
/// or invoke a second cryptographic verification after the P1363 check fails.
/// </summary>
public class EcdsaInvalidSignatureAllocationTests
{
    [Theory]
    [InlineData(SignatureAlgorithm.ES256)]
    [InlineData(SignatureAlgorithm.ES384)]
    [InlineData(SignatureAlgorithm.ES512)]
    public void Should_NotAllocateDerFallback_When_JoseSignatureIsInvalid(SignatureAlgorithm algorithm)
    {
        var curve = algorithm switch
        {
            SignatureAlgorithm.ES256 => ECCurve.NamedCurves.nistP256,
            SignatureAlgorithm.ES384 => ECCurve.NamedCurves.nistP384,
            SignatureAlgorithm.ES512 => ECCurve.NamedCurves.nistP521,
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm))
        };

        using var ecdsa = ECDsa.Create(curve);
        var publicKey = ecdsa.ExportSubjectPublicKeyInfo();
        var jwt = new JwtSigner().CreateJwt(
            new Dictionary<string, object> { ["sub"] = "ecdsa-allocation-regression" },
            ecdsa.ExportPkcs8PrivateKey(), algorithm);

        var parts = jwt.Split('.');
        var invalidSignature = Base64UrlEncoder.DecodeBytes(parts[2]);
        invalidSignature[^1] ^= 1;
        var invalidJwt = $"{parts[0]}.{parts[1]}.{Base64UrlEncoder.Encode(invalidSignature)}";

        var validator = new SignatureValidator();
        Assert.True(validator.VerifyJwtSignature(jwt, publicKey));
        Assert.False(validator.VerifyJwtSignature(invalidJwt, publicKey));

        // Warm both paths before measuring managed allocations, including
        // any one-time native crypto initialization on the current thread.
        for (var i = 0; i < 16; i++)
        {
            _ = validator.VerifyJwtSignature(jwt, publicKey);
            _ = validator.VerifyJwtSignature(invalidJwt, publicKey);
        }

        var validAllocations = MeasureAllocations(validator, jwt, publicKey);
        var rejectedAllocations = MeasureAllocations(validator, invalidJwt, publicKey);

        // Both calls parse the same header and identical-length JWT segments.
        // A failed raw JOSE verification must not construct a DER signature and
        // retry cryptography. Allow a modest margin for runtime differences.
        Assert.True(
            rejectedAllocations <= validAllocations + 8_192,
            $"Rejected {algorithm} signature allocated {rejectedAllocations} bytes " +
            $"versus {validAllocations} for a valid signature.");
    }

    private static long MeasureAllocations(SignatureValidator validator, string jwt, byte[] publicKey)
    {
        var before = GC.GetAllocatedBytesForCurrentThread();
        for (var i = 0; i < 128; i++)
        {
            _ = validator.VerifyJwtSignature(jwt, publicKey);
        }

        return GC.GetAllocatedBytesForCurrentThread() - before;
    }
}
