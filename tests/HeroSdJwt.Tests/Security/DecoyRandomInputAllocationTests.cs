using HeroSdJwt.Issuance;
using System.Buffers.Text;
using System.Security.Cryptography;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Decoy generation is a per-credential hot path: its random input should not
/// allocate a temporary byte array for each decoy digest.
/// </summary>
public class DecoyRandomInputAllocationTests
{
    [Fact]
    public void Should_NotAllocateRandomByteArrayForEveryDecoy()
    {
        const int count = 256;
        var generator = new DecoyDigestGenerator(new ConstantDigestCalculator());

        // Warm up both paths so JIT and crypto initialization do not affect
        // the allocation comparison.
        _ = generator.GenerateDecoyDigests(1, HashAlgorithm.Sha256);
        _ = GenerateReference(1);

        var before = GC.GetAllocatedBytesForCurrentThread();
        var actual = generator.GenerateDecoyDigests(count, HashAlgorithm.Sha256);
        var actualBytes = GC.GetAllocatedBytesForCurrentThread() - before;

        before = GC.GetAllocatedBytesForCurrentThread();
        var reference = GenerateReference(count);
        var referenceBytes = GC.GetAllocatedBytesForCurrentThread() - before;

        Assert.Equal(count, actual.Count);
        // The reference performs the same RNG and encoding work, retaining
        // the same number of 43-character output strings. Allow modest
        // overhead for the injected calculator, but not a 32-byte heap array
        // (56 bytes including object overhead) for each decoy.
        Assert.True(
            actualBytes <= referenceBytes + 24L * count,
            $"Decoys allocated {actualBytes:N0} bytes; the equivalent stack-backed " +
            $"reference allocated {referenceBytes:N0} bytes for {count} decoys.");

        GC.KeepAlive(actual);
        GC.KeepAlive(reference);
    }

    private static List<string> GenerateReference(int count)
    {
        var encoded = new List<string>(count);
        Span<byte> randomBytes = stackalloc byte[32];
        for (var i = 0; i < count; i++)
        {
            RandomNumberGenerator.Fill(randomBytes);
            encoded.Add(Base64Url.EncodeToString(randomBytes));
        }

        return encoded;
    }

    private sealed class ConstantDigestCalculator : IDigestCalculator
    {
        public string ComputeDigest(string disclosure, HashAlgorithm algorithm) => "digest";
    }
}
