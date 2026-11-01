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
    private const int ImpossibleDecoyCount = Constants.MAX_JWT_SIZE_BYTES / 43 + 1;

    private static readonly byte[] _signingKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Fact]
    public void Should_RejectImpossibleDecoyCount_BeforeGeneratorAllocates()
    {
        var generator = new DecoyDigestGenerator(new DigestCalculator());

        var exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
            generator.GenerateDecoyDigests(ImpossibleDecoyCount, HashAlgorithm.Sha256));

        Assert.Equal("count", exception.ParamName);
    }

    [Fact]
    public void Should_RejectImpossibleDecoyCount_AtLowLevelIssuer()
    {
        var exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
            TestHelpers.CreateIssuer().CreateSdJwt(
                new Dictionary<string, object> { ["email"] = "holder@example.test" },
                ["email"],
                _signingKey,
                HashAlgorithm.Sha256,
                decoyDigestCount: ImpossibleDecoyCount));

        Assert.Equal("decoyDigestCount", exception.ParamName);
    }

    [Fact]
    public void Should_RejectImpossibleDecoyCount_AtBuilderConfiguration()
    {
        var exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
            SdJwtIssuerBuilder.Create().WithDecoys(ImpossibleDecoyCount));

        Assert.Equal("count", exception.ParamName);
    }
}
