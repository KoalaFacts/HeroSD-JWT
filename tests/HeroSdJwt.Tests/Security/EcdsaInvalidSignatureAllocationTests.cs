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

        // Native ECDSA providers may allocate differently for a rejected
        // signature, notably P-521 on Linux. Alternate measurement order and
        // use the median pair to avoid false failures from provider jitter.
        const int SampleCount = 9;
        var differences = new long[SampleCount];
        for (var i = 0; i < SampleCount; i++)
        {
            long validAllocations;
            long rejectedAllocations;
            if ((i & 1) == 0)
            {
                validAllocations = MeasureAllocations(validator, jwt, publicKey);
                rejectedAllocations = MeasureAllocations(validator, invalidJwt, publicKey);
            }
            else
            {
                rejectedAllocations = MeasureAllocations(validator, invalidJwt, publicKey);
                validAllocations = MeasureAllocations(validator, jwt, publicKey);
            }

            differences[i] = rejectedAllocations - validAllocations;
        }

        Array.Sort(differences);
        var medianExtraBytes = differences[SampleCount / 2];

        // Both calls parse identical-length JWT segments. The old DER
        // fallback allocated over 175 KiB extra per 128 invalid verifications.
        // Allow 32 KiB for native crypto differences, still far below that
        // regression; keep the invalid/valid comparison and full assertions.
        Assert.True(
            medianExtraBytes <= 32_768,
            $"Rejected {algorithm} signature median extra allocation was {medianExtraBytes} bytes " +
            $"per 128 verifications (range {differences[0]}..{differences[^1]} bytes).");
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
