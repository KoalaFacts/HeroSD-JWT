using HeroSdJwt.Encoding;
using System.Buffers.Text;
using BclTextEncoding = System.Text.Encoding;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// The short-text JOSE encoding path must preserve strict UTF-8 byte semantics
/// without allocating a new temporary byte array for every invocation.
/// </summary>
public class ShortTextBase64UrlAllocationTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(255)]
    [InlineData(256)]
    [InlineData(257)]
    public void Should_PreserveUtf8Encoding_AcrossStackBufferThreshold(int length)
    {
        foreach (var value in new[] { 'A', 'é', '界' })
        {
            var text = new string(value, length);
            var expected = Base64Url.EncodeToString(BclTextEncoding.UTF8.GetBytes(text));

            Assert.Equal(expected, Base64UrlEncoder.Encode(text));
        }
    }

    [Fact]
    public void Should_PreserveUtf8Encoding_ForSurrogatePairsAtStackLimit()
    {
        var text = string.Concat(Enumerable.Repeat("🦘", 128));
        var expected = Base64Url.EncodeToString(BclTextEncoding.UTF8.GetBytes(text));

        Assert.Equal(256, text.Length);
        Assert.Equal(expected, Base64UrlEncoder.Encode(text));
        Assert.Equal(text, Base64UrlEncoder.DecodeString(expected));
    }

    [Fact]
    public void Should_NotAllocateTemporaryUtf8Array_ForShortText()
    {
        const int iterations = 256;
        var text = new string('Z', 240);
        var preEncodedUtf8 = BclTextEncoding.UTF8.GetBytes(text);

        // Both paths create the same encoded output string. The reference
        // uses caller-owned bytes so it never allocates a UTF-8 input array.
        for (var i = 0; i < 128; i++)
        {
            _ = Base64UrlEncoder.Encode(text);
            _ = Base64Url.EncodeToString(preEncodedUtf8);
        }

        var actualBytes = MeasureAllocatedBytes(() => Base64UrlEncoder.Encode(text), iterations);
        var referenceBytes = MeasureAllocatedBytes(() => Base64Url.EncodeToString(preEncodedUtf8), iterations);

        // The old Encoding.UTF8.GetBytes(string) path allocated another
        // ~264 bytes per call for this input. Allow limited method overhead,
        // but no input-sized array on each invocation.
        Assert.True(
            actualBytes <= referenceBytes + 48L * iterations,
            $"Short text encoding allocated {actualBytes / iterations} bytes/call; " +
            $"stack-compatible reference allocated {referenceBytes / iterations} bytes/call.");
    }

    private static long MeasureAllocatedBytes(Func<string> encode, int iterations)
    {
        var before = GC.GetAllocatedBytesForCurrentThread();
        for (var i = 0; i < iterations; i++)
        {
            var encoded = encode();
            GC.KeepAlive(encoded);
        }

        return GC.GetAllocatedBytesForCurrentThread() - before;
    }
}
