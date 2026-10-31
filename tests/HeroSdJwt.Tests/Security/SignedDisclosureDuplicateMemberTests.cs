using HeroSdJwt.Encoding;
using HeroSdJwt.Issuance;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;
using System.Text.Json;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// A valid issuer signature and matching disclosure digest must not authenticate
/// ambiguous nested JSON object member names.
/// </summary>
public class SignedDisclosureDuplicateMemberTests
{
    private static readonly byte[] _key = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Theory]
    [InlineData(/*lang=json,strict*/ """["salt","profile",{"role":"reader","role":"admin"}]""")]
    [InlineData(/*lang=json,strict*/ """["salt","profile",{"role":"reader","\u0072ole":"admin"}]""")]
    [InlineData(/*lang=json,strict*/ """["salt","profile",{"team":{"role":"reader","role":"admin"}}]""")]
    [InlineData(/*lang=json,strict*/ """["salt","profile",[{"role":"reader","role":"admin"}]]""")]
    [InlineData(/*lang=json,strict*/ """["salt",{"role":"reader","role":"admin"}]""")]
    public async Task Should_RejectSignedDisclosureWithAmbiguousNestedNames(string json)
    {
        var presentation = CreateSignedPresentation(json);
        var verifier = CreateVerifier();

        var direct = verifier.TryVerifyPresentation(presentation, _key);
        Assert.False(direct.IsValid);

        var asyncResult = await verifier.TryVerifyPresentationAsync(
            presentation, _key, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(asyncResult.IsValid);
    }

    [Fact]
    public void Should_AllowDistinctNestedObjectsWithMatchingMemberNames()
    {
        const string json = /*lang=json,strict*/ """["salt","profile",{"primary":{"role":"admin"},"secondary":{"role":"reader"}}]""";
        var presentation = CreateSignedPresentation(json);
        var result = CreateVerifier().TryVerifyPresentation(presentation, _key);

        Assert.True(result.IsValid, result.ErrorDetails);
        var profile = result.DisclosedClaims["profile"];
        Assert.Equal("admin", profile.GetProperty("primary").GetProperty("role").GetString());
        Assert.Equal("reader", profile.GetProperty("secondary").GetProperty("role").GetString());
    }

    private static SdJwtVerifier CreateVerifier() =>
        SdJwtVerifierBuilder.Create().WithExpectedKeyType(VerificationKeyType.Symmetric).Build();

    private static string CreateSignedPresentation(string disclosureJson)
    {
        var disclosure = Base64UrlEncoder.Encode(disclosureJson);
        var digest = new DigestCalculator().ComputeDigest(disclosure, HashAlgorithm.Sha256);
        var payload = JsonSerializer.Serialize(new { exp = 4102444800L, _sd = new[] { digest } });
        const string header = /*lang=json,strict*/ "{\"alg\":\"HS256\"}";
        var input = Base64UrlEncoder.Encode(header) + "." + Base64UrlEncoder.Encode(payload);
        var signature = HMACSHA256.HashData(_key, System.Text.Encoding.UTF8.GetBytes(input));
        return input + "." + Base64UrlEncoder.Encode(signature) + "~" + disclosure + "~";
    }
}
