using HeroSdJwt.KeyBinding;
using HeroSdJwt.Primitives;
using System.Security.Cryptography;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Impossible holder proofs must be rejected before the generator consults the
/// clock or allocates the JSON/UTF-8/base64 representations of untrusted input.
/// </summary>
public sealed class KeyBindingPreSerializationSizeTests
{
    [Theory]
    [InlineData("sdJwtHash")]
    [InlineData("audience")]
    [InlineData("nonce")]
    public void Should_RejectOversizedIndividualInputBeforeReadingClock(string oversizedParameter)
    {
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var oversized = new string('x', Constants.MAX_JWT_SIZE_BYTES + 1);
        var generator = new KeyBindingGenerator(new ThrowingTimeProvider());

        var error = Assert.Throws<ArgumentException>(() => generator.CreateKeyBindingJwt(
            holder.ExportECPrivateKey(),
            oversizedParameter == "sdJwtHash" ? oversized : "hash",
            oversizedParameter == "audience" ? oversized : "https://verifier.example.test",
            oversizedParameter == "nonce" ? oversized : "one-time-challenge"));

        Assert.Equal(oversizedParameter, error.ParamName);
    }

    [Fact]
    public void Should_RejectOversizedCombinedInputBeforeReadingClock()
    {
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var generator = new KeyBindingGenerator(new ThrowingTimeProvider());
        var part = new string('a', 22_000);

        // None of the individual values exceeds 64 KiB, but together they
        // cannot fit in a 64-KiB compact JWT even before JSON/base64 overhead.
        _ = Assert.Throws<ArgumentException>(() => generator.CreateKeyBindingJwt(
            holder.ExportECPrivateKey(), part, part, part));
    }

    private sealed class ThrowingTimeProvider : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() =>
            throw new InvalidOperationException("Oversized input must be rejected before reading the clock.");
    }
}
