using HeroSdJwt.Models;
using HeroSdJwt.Presentation;
using HeroSdJwt.Primitives;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Combined-format serialization is a hot path for holders that transmit credentials.
/// It should allocate its output string without allocating an intermediate list and
/// backing arrays for every presentation.
/// </summary>
public class CombinedFormatAllocationTests
{
    [Fact]
    public void Should_AllocateOnlyTheOutputString_When_SerializingSdJwt()
    {
        var sdJwt = new SdJwt(
            "header.payload.signature",
            ["WzEsMl0", "WzMsNF0", "WzUsNl0", "WzcsOF0"],
            HashAlgorithm.Sha256,
            keyBindingJwt: "key.binding.jwt");
        var presentation = new SdJwtPresentation(
            sdJwt.Jwt, sdJwt.Disclosures, sdJwt.KeyBindingJwt);
        var presenter = new SdJwtPresenter();

        Func<string> serializeSdJwt = sdJwt.ToCombinedFormat;
        Func<string> serializePresentation = () => presenter.FormatPresentation(presentation);

        // Preserve the exact wire format, including the final key binding JWT.
        Assert.Equal(serializePresentation(), serializeSdJwt());

        // Warm up both code paths before measuring per-thread allocations.
        for (var i = 0; i < 128; i++)
        {
            _ = serializeSdJwt();
            _ = serializePresentation();
        }

        const int iterations = 512;
        var outputOnlyBytes = MeasureAllocatedBytes(serializePresentation, iterations);
        var sdJwtBytes = MeasureAllocatedBytes(serializeSdJwt, iterations);

        // The presenter already writes directly into the output string. The
        // SdJwt API should not add an intermediate List<string> and two arrays.
        Assert.True(
            sdJwtBytes <= outputOnlyBytes + 64L * iterations,
            $"SdJwt.ToCombinedFormat allocated {sdJwtBytes / iterations} bytes/call; " +
            $"direct formatting allocated {outputOnlyBytes / iterations} bytes/call.");
    }

    private static long MeasureAllocatedBytes(Func<string> serializer, int iterations)
    {
        var before = GC.GetAllocatedBytesForCurrentThread();
        for (var i = 0; i < iterations; i++)
        {
            var result = serializer();
            GC.KeepAlive(result);
        }

        return GC.GetAllocatedBytesForCurrentThread() - before;
    }
}
