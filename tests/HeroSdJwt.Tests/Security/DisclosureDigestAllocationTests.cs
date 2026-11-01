using HeroSdJwt.Encoding;
using HeroSdJwt.Issuance;
using System.Security.Cryptography;
using System.Text;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Short disclosure digests are calculated for every issued and verified claim.
/// They should not allocate a new UTF-8 input array on each invocation.
/// </summary>
public class DisclosureDigestAllocationTests
{
    [Theory]
    [InlineData(HashAlgorithm.Sha256)]
    [InlineData(HashAlgorithm.Sha384)]
    [InlineData(HashAlgorithm.Sha512)]
    public void Should_NotAllocateProportionalUtf8InputArray_ForShortDisclosures(HashAlgorithm algorithm)
    {
        var calculator = new DigestCalculator();
        var shorter = new string('A', 32);
        var longer = new string('B', 240);

        for (var i = 0; i < 128; i++)
        {
            _ = calculator.ComputeDigest(shorter, algorithm);
            _ = calculator.ComputeDigest(longer, algorithm);
        }

        const int iterations = 256;
        var shorterBytes = MeasureAllocatedBytes(calculator, shorter, algorithm, iterations);
        var longerBytes = MeasureAllocatedBytes(calculator, longer, algorithm, iterations);

        // Hash digests have the same output size regardless of disclosure length.
        // The previous UTF8.GetBytes(string) path allocated a byte[] proportional
        // to disclosure length (~208 bytes more per call for this pair).
        Assert.True(
            longerBytes <= shorterBytes + 48L * iterations,
            $"Digest {algorithm}: short input allocated {shorterBytes / iterations} bytes/call; " +
            $"long input allocated {longerBytes / iterations} bytes/call.");
    }

    [Theory]
    [InlineData(HashAlgorithm.Sha256)]
    [InlineData(HashAlgorithm.Sha384)]
    [InlineData(HashAlgorithm.Sha512)]
    public void Should_PreserveUtf8Digest_ForShortNonAsciiDisclosure(HashAlgorithm algorithm)
    {
        var disclosure = new string('é', 240);
        var bytes = Encoding.UTF8.GetBytes(disclosure);
        var hash = algorithm switch
        {
            HashAlgorithm.Sha256 => SHA256.HashData(bytes),
            HashAlgorithm.Sha384 => SHA384.HashData(bytes),
            HashAlgorithm.Sha512 => SHA512.HashData(bytes),
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm))
        };

        Assert.Equal(Base64UrlEncoder.Encode(hash), new DigestCalculator().ComputeDigest(disclosure, algorithm));
    }

    private static long MeasureAllocatedBytes(
        DigestCalculator calculator, string disclosure, HashAlgorithm algorithm, int iterations)
    {
        var before = GC.GetAllocatedBytesForCurrentThread();
        for (var i = 0; i < iterations; i++)
        {
            var digest = calculator.ComputeDigest(disclosure, algorithm);
            GC.KeepAlive(digest);
        }

        return GC.GetAllocatedBytesForCurrentThread() - before;
    }
}
