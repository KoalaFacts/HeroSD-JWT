using HeroSdJwt.Issuance;
using HeroSdJwt.Primitives;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// A decoy count that cannot fit in the library's maximum JWT size must be
/// rejected before allocating or hashing the requested number of decoys.
/// </summary>
public class OversizedDecoyCountAdmissionTests
{
    // Even SHA-256's shortest possible digest occupies 43 characters before
    // JSON quoting, separators, and JWT base64url expansion.
    private const int IMPOSSIBLE_DECOY_COUNT = Constants.MAX_JWT_SIZE_BYTES / 43 + 1;

    private static readonly byte[] _signingKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Theory]
    [InlineData(IMPOSSIBLE_DECOY_COUNT)]
    [InlineData(int.MaxValue)]
    public void Should_RejectImpossibleDecoyCount_BeforeGeneratorAllocates(int count)
    {
        var generator = new DecoyDigestGenerator(new DigestCalculator());

        var exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
            generator.GenerateDecoyDigests(count, HashAlgorithm.Sha256));

        Assert.Equal("count", exception.ParamName);
    }

    [Theory]
    [InlineData(IMPOSSIBLE_DECOY_COUNT)]
    [InlineData(int.MaxValue)]
    public void Should_RejectImpossibleDecoyCount_AtLowLevelIssuer(int count)
    {
        var exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
            TestHelpers.CreateIssuer().CreateSdJwt(
                new Dictionary<string, object> { ["email"] = "holder@example.test" },
                ["email"],
                _signingKey,
                HashAlgorithm.Sha256,
                decoyDigestCount: count));

        Assert.Equal("decoyDigestCount", exception.ParamName);
    }

    [Theory]
    [InlineData(IMPOSSIBLE_DECOY_COUNT)]
    [InlineData(int.MaxValue)]
    public void Should_RejectImpossibleDecoyCount_AtBuilderConfiguration(int count)
    {
        var exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
            SdJwtIssuerBuilder.Create().WithDecoys(count));

        Assert.Equal("count", exception.ParamName);
    }
}
