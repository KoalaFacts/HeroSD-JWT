using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Issuance;
using HeroSdJwt.Models;
using HeroSdJwt.Presentation;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;
using System.Text.Json;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Signed disclosures must not admit string values with unpaired Unicode
/// surrogates, including values nested inside arrays or objects.
/// </summary>
public class DisclosureClaimValueUnicodeAdmissionTests
{
    private static readonly byte[] _key = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Theory]
    [InlineData(/*lang=json,strict*/ """["salt","profile","\uD800"]""")]
    [InlineData(/*lang=json,strict*/ """["salt","profile",{"nested":"\uDC00"}]""")]
    [InlineData(/*lang=json,strict*/ """["salt","profile",[{"nested":["\uD800"]}]]""")]
    [InlineData(/*lang=json,strict*/ """["salt",["\uDC00"]]""")]
    public async Task Should_RejectSignedDisclosureWithInvalidUnicodeInClaimValue(string json)
    {
        var encoded = Base64UrlEncoder.Encode(json);
        var digest = new DigestCalculator().ComputeDigest(encoded, HashAlgorithm.Sha256);
        var payload = JsonSerializer.Serialize(new { exp = 4102444800L, _sd = new[] { digest } });
        const string header = /*lang=json,strict*/ """{"alg":"HS256"}""";
        var signingInput = Base64UrlEncoder.Encode(header) + "." + Base64UrlEncoder.Encode(payload);
        var signature = HMACSHA256.HashData(_key, System.Text.Encoding.UTF8.GetBytes(signingInput));
        var presentation = signingInput + "." + Base64UrlEncoder.Encode(signature) + "~" + encoded + "~";
        var verifier = SdJwtVerifierBuilder.Create()
            .WithExpectedKeyType(VerificationKeyType.Symmetric)
            .Build();

        Assert.Throws<MalformedDisclosureException>(() => new DisclosureParser().Parse(encoded));
        Assert.False(verifier.TryVerifyPresentation(presentation, _key).IsValid);

        var asyncResult = await verifier.TryVerifyPresentationAsync(
            presentation, _key, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(asyncResult.IsValid);
    }

    [Theory]
    [InlineData("\"\\uD800\"")]
    [InlineData(/*lang=json,strict*/ """{"nested":"\uDC00"}""")]
    [InlineData(/*lang=json,strict*/ """[{"nested":["\uD800"]}]""")]
    public void Should_RejectInvalidUnicodeFromDirectDisclosureConstructors(string claimValueJson)
    {
        using var document = JsonDocument.Parse(claimValueJson);

        Assert.Throws<ArgumentException>(() => new Disclosure("salt", "profile", document.RootElement));
        Assert.Throws<ArgumentException>(() => new Disclosure("salt", document.RootElement));
    }

    [Fact]
    public void Should_PreserveValidEscapedSurrogatePairsInNestedValues()
    {
        using var document = JsonDocument.Parse(/*lang=json,strict*/ """{"nested":["\uD83D\uDE00"]}""");
        var disclosure = new Disclosure("salt", "profile", document.RootElement);
        var encoded = Base64UrlEncoder.Encode(disclosure.ToJson());
        var parsed = new DisclosureParser().Parse(encoded);

        Assert.Equal("😀", parsed.ClaimValue.GetProperty("nested")[0].GetString());
    }
}
