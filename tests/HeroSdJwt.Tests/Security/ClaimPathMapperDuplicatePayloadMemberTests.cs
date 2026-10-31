using HeroSdJwt.Encoding;
using HeroSdJwt.Issuance;
using HeroSdJwt.Models;
using HeroSdJwt.Presentation;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// The holder's on-demand claim-path mapper must not interpret an ambiguous
/// issuer JWT differently from the verifier when preparing disclosures.
/// </summary>
public class ClaimPathMapperDuplicatePayloadMemberTests
{
    [Theory]
    [InlineData(/*lang=json,strict*/ """{"_sd":[],"_sd":[]}""")]
    [InlineData(/*lang=json,strict*/ """{"profile":{"role":"reader","role":"admin"},"_sd":[]}""")]
    [InlineData(/*lang=json,strict*/ """{"profile":[{"role":"reader","\\u0072ole":"admin"}],"_sd":[]}""")]
    public void Should_RejectDuplicatePayloadMembersBeforeMappingDisclosures(string payload)
    {
        var sdJwt = CreateSdJwt(payload, []);

        _ = Assert.Throws<ArgumentException>(() =>
            new DisclosureClaimPathMapper().BuildClaimPathMapping(sdJwt));
    }

    [Fact]
    public void Should_AcceptIdenticalMemberNamesInDistinctObjects()
    {
        var disclosure = Base64UrlEncoder.Encode(/*lang=json,strict*/ """["salt","email","person@example.com"]""");
        var digest = new DigestCalculator().ComputeDigest(disclosure, HashAlgorithm.Sha256);
        var payload = "{\"profile\":{\"primary\":{\"role\":\"reader\"},\"secondary\":{\"role\":\"admin\"}},\"_sd\":[\"" + digest + "\"]}";
        var sdJwt = CreateSdJwt(payload, [disclosure]);

        var mapping = new DisclosureClaimPathMapper().BuildClaimPathMapping(sdJwt);

        Assert.Equal(0, mapping["email"]);
    }

    private static SdJwt CreateSdJwt(string payload, string[] disclosures)
    {
        var jwt = Base64UrlEncoder.Encode(/*lang=json,strict*/ """{"alg":"HS256"}""") +
                  "." + Base64UrlEncoder.Encode(payload) + ".signature";
        return new SdJwt(jwt, disclosures, HashAlgorithm.Sha256);
    }
}
