using HeroSdJwt.Cryptography;
using HeroSdJwt.Issuance;
using HeroSdJwt.Primitives;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// JWT claims can contain lazy IEnumerable values. Serialization must stop
/// before a hostile stream grows an impossible-to-verify token indefinitely.
/// </summary>
public sealed class JwtSignerLazyClaimSerializationTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Should_StopEnumeratingOversizedNestedClaimStream_When_SigningOrSnapshotting(bool useBuilder)
    {
        var itemsEnumerated = 0;

        IEnumerable<string> OversizedItems()
        {
            while (true)
            {
                if (++itemsEnumerated > 50_000)
                {
                    throw new InvalidOperationException("The claim source was consumed beyond its safety sentinel.");
                }

                yield return "value";
            }
        }

        var nestedClaim = new Dictionary<string, object>
        {
            ["items"] = OversizedItems()
        };
        var signingKey = new byte[32];

        void CreateWithBuilder()
        {
            _ = SdJwtIssuerBuilder.Create()
                .WithClaim("sub", "holder")
                .WithClaim("profile", nestedClaim)
                .SignWithHmac(signingKey)
                .Build();
        }

        void CreateWithSigner()
        {
            _ = new JwtSigner().CreateJwt(
                new Dictionary<string, object>
                {
                    ["sub"] = "holder",
                    ["profile"] = nestedClaim
                },
                signingKey,
                SignatureAlgorithm.HS256);
        }

        Action createCredential = useBuilder ? CreateWithBuilder : CreateWithSigner;

        var exception = Assert.Throws<ArgumentException>(createCredential);
        Assert.Contains("maximum allowed size", exception.Message);
        Assert.InRange(itemsEnumerated, 1, 50_000);
    }
}
