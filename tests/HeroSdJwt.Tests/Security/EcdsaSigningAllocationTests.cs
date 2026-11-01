using HeroSdJwt.Cryptography;
using HeroSdJwt.Primitives;
using System.Reflection;
using System.Security.Cryptography;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// ECDSA signing must return the P1363 signature produced by .NET without
/// allocating an unnecessary second signature array for every issued JWT.
/// </summary>
public class EcdsaSigningAllocationTests
{
    [Theory]
    [InlineData(SignatureAlgorithm.ES256, "SignEcdsa256", 64)]
    [InlineData(SignatureAlgorithm.ES384, "SignEcdsa384", 96)]
    [InlineData(SignatureAlgorithm.ES512, "SignEcdsa512", 132)]
    public void Should_AvoidCopyingRawSignature_When_SigningEcdsa(
        SignatureAlgorithm algorithm,
        string methodName,
        int expectedSignatureSize)
    {
        var (curve, hash, curveOid) = algorithm switch
        {
            SignatureAlgorithm.ES256 => (ECCurve.NamedCurves.nistP256, HashAlgorithmName.SHA256, "1.2.840.10045.3.1.7"),
            SignatureAlgorithm.ES384 => (ECCurve.NamedCurves.nistP384, HashAlgorithmName.SHA384, "1.3.132.0.34"),
            SignatureAlgorithm.ES512 => (ECCurve.NamedCurves.nistP521, HashAlgorithmName.SHA512, "1.3.132.0.35"),
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm))
        };

        using var key = ECDsa.Create(curve);
        var privateKey = key.ExportPkcs8PrivateKey();
        var signingInput = System.Text.Encoding.ASCII.GetBytes("header.payload");

        // The existing private signing entry points are measured directly to
        // isolate the signature copy from JSON, Base64, and JWT construction.
        var method = typeof(JwtSigner).GetMethod(methodName, BindingFlags.NonPublic | BindingFlags.Static)
            ?? throw new InvalidOperationException($"Missing signing method: {methodName}");
        var sign = method.CreateDelegate<Func<byte[], byte[], byte[]>>();
        byte[] DirectSign()
        {
            return SignP1363(signingInput, privateKey, hash, curveOid);
        }

        byte[] ProductSign()
        {
            return sign(signingInput, privateKey);
        }

        var signature = ProductSign();
        Assert.Equal(expectedSignatureSize, signature.Length);
        Assert.True(key.VerifyData(
            signingInput, signature, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));

        for (var i = 0; i < 12; i++)
        {
            _ = DirectSign();
            _ = ProductSign();
        }

        // Native ECDSA signing can have uneven allocation outliers across
        // independent signatures, especially with P-521 on Windows. Measure
        // adjacent direct/product calls in alternating order and compare the
        // median pair, rather than two long batches skewed by provider state.
        const int SampleCount = 129;
        var differences = new long[SampleCount];
        for (var i = 0; i < SampleCount; i++)
        {
            long directBytes;
            long productBytes;
            if ((i & 1) == 0)
            {
                directBytes = MeasureAllocations(DirectSign);
                productBytes = MeasureAllocations(ProductSign);
            }
            else
            {
                productBytes = MeasureAllocations(ProductSign);
                directBytes = MeasureAllocations(DirectSign);
            }

            differences[i] = productBytes - directBytes;
        }

        Array.Sort(differences);
        var medianExtraBytes = differences[SampleCount / 2];

        // Both paths import the same PKCS#8 key, check the curve and use
        // the same .NET signing overload. The old DER-to-JOSE fallback copied
        // every P1363 signature (at least 88 managed bytes for ES256).
        // The 64-byte allowance is smaller than that extra array allocation.
        Assert.True(
            medianExtraBytes <= 64,
            $"{algorithm}: median extra allocation was {medianExtraBytes} bytes " +
            $"per signature (range {differences[0]}..{differences[^1]} bytes).");
    }

    private static byte[] SignP1363(
        byte[] data, byte[] privateKey, HashAlgorithmName hash, string curveOid)
    {
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportPkcs8PrivateKey(privateKey, out var bytesRead);
        if (bytesRead != privateKey.Length)
        {
            throw new ArgumentException("Trailing key bytes", nameof(privateKey));
        }

        if (ecdsa.ExportParameters(false).Curve.Oid?.Value != curveOid)
        {
            throw new ArgumentException("Wrong ECDSA curve", nameof(privateKey));
        }

        // Match the product's exact .NET overload. Its documented default
        // output is already IEEE P1363 on .NET 8/9/10.
        return ecdsa.SignData(data, hash);
    }

    private static long MeasureAllocations(Func<byte[]> sign)
    {
        var before = GC.GetAllocatedBytesForCurrentThread();
        var signature = sign();
        GC.KeepAlive(signature);
        return GC.GetAllocatedBytesForCurrentThread() - before;
    }
}
