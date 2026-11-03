using HeroSdJwt.Issuance;
using HeroSdJwt.Primitives;
using System.Security.Cryptography;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Direct disclosure hashing must not allocate arbitrarily large UTF-8 input
/// buffers for text that cannot fit in a verifiable SD-JWT presentation.
/// </summary>
public class DirectDigestSizeAdmissionTests
{
    [Theory]
    [InlineData(HashAlgorithm.Sha256)]
    [InlineData(HashAlgorithm.Sha384)]
    [InlineData(HashAlgorithm.Sha512)]
    public void Should_RejectOversizedAsciiDisclosure_BeforeAllocatingUtf8Input(HashAlgorithm algorithm)
    {
        var calculator = new DigestCalculator();
        var disclosure = new string('A', 2 * 1024 * 1024);

        // Measure only the attempted digest: the caller-owned text is already allocated.
        var before = GC.GetAllocatedBytesForCurrentThread();
        var exception = Assert.Throws<ArgumentException>(() => calculator.ComputeDigest(disclosure, algorithm));
        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        Assert.Equal("disclosure", exception.ParamName);
        Assert.True(allocated < 64 * 1024, $"Rejected input allocated {allocated} bytes.");
    }

    [Theory]
    [InlineData(HashAlgorithm.Sha256)]
    [InlineData(HashAlgorithm.Sha384)]
    [InlineData(HashAlgorithm.Sha512)]
    public void Should_RejectOversizedUtf8Disclosure_WhenUtf16LengthFits(HashAlgorithm algorithm)
    {
        // 30,000 UTF-16 characters are 90,000 UTF-8 bytes.
        var disclosure = new string('界', 30_000);
        var exception = Assert.Throws<ArgumentException>(() =>
            new DigestCalculator().ComputeDigest(disclosure, algorithm));

        Assert.Equal("disclosure", exception.ParamName);
    }

    [Theory]
    [InlineData(HashAlgorithm.Sha256)]
    [InlineData(HashAlgorithm.Sha384)]
    [InlineData(HashAlgorithm.Sha512)]
    public void Should_AcceptAsciiDisclosureAtWireLimit(HashAlgorithm algorithm)
    {
        var disclosure = new string('A', Constants.MAX_JWT_SIZE_BYTES);
        var input = System.Text.Encoding.ASCII.GetBytes(disclosure);
        byte[] expected = algorithm switch
        {
            HashAlgorithm.Sha256 => SHA256.HashData(input),
            HashAlgorithm.Sha384 => SHA384.HashData(input),
            HashAlgorithm.Sha512 => SHA512.HashData(input),
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm))
        };

        Assert.Equal(
            Encoding.Base64UrlEncoder.Encode(expected),
            new DigestCalculator().ComputeDigest(disclosure, algorithm));
    }
}
