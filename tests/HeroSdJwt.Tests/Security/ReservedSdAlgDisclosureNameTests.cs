using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Issuance;
using HeroSdJwt.Presentation;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;
using System.Text.Json;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// RFC 9901 permits _sd_alg only as an issuer JWT top-level control member.
/// A Disclosure must never introduce or relocate that control member.
/// </summary>
public class ReservedSdAlgDisclosureNameTests
{
    private static readonly byte[] _signingKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Fact]
    public void Should_RejectSdAlgAsObjectDisclosureNameAtParserBoundary()
    {
        var disclosure = Base64UrlEncoder.Encode("""["salt","_sd_alg","sha-512"]""");

        Assert.Throws<MalformedDisclosureException>(() => new DisclosureParser().Parse(disclosure));
    }

    [Theory]
    [InlineData("root")]
    [InlineData("nested")]
    [InlineData("array")]
    [InlineData("disclosed-parent")]
    public async Task Should_RejectReservedHashAlgorithmDisclosureInSignedPresentation(string placement)
    {
        var disclosure = Base64UrlEncoder.Encode("""["salt-leaf","_sd_alg","sha-512"]""");
        var digest = new DigestCalculator().ComputeDigest(disclosure, HashAlgorithm.Sha256);

        (string payload, string[] disclosures) = placement switch
        {
            "root" => (
                JsonSerializer.Serialize(new { exp = 4102444800L, _sd = new[] { digest } }),
                [disclosure]),
            "nested" => (
                JsonSerializer.Serialize(new { exp = 4102444800L, profile = new { _sd = new[] { digest } } }),
                [disclosure]),
            "array" => (
                JsonSerializer.Serialize(new { exp = 4102444800L, records = new[] { new { _sd = new[] { digest } } } }),
                [disclosure]),
            "disclosed-parent" => CreateNestedDisclosures(disclosure, digest),
            _ => throw new ArgumentOutOfRangeException(nameof(placement))
        };

        await AssertRejectedAsync(SignPayload(payload) + "~" + string.Join("~", disclosures) + "~");
    }

    [Fact]
    public async Task Should_AcceptSignedRootHashAlgorithmAndNonreservedDisclosedName()
    {
        var disclosure = Base64UrlEncoder.Encode("""["salt-good","_sd_algorithm","safe"]""");
        var digest = new DigestCalculator().ComputeDigest(disclosure, HashAlgorithm.Sha256);
        var payload = JsonSerializer.Serialize(new
        {
            exp = 4102444800L,
            _sd_alg = "sha-256",
            _sd = new[] { digest }
        });
        var presentation = SignPayload(payload) + "~" + disclosure + "~";
        var verifier = CreateVerifier();

        var direct = verifier.TryVerifyPresentation(presentation, _signingKey);
        Assert.True(direct.IsValid, direct.ErrorDetails);
        Assert.Equal("safe", direct.DisclosedClaims["_sd_algorithm"].GetString());

        var resolved = verifier.TryVerifyPresentation(presentation, ResolveKey);
        Assert.True(resolved.IsValid, resolved.ErrorDetails);

        var asyncDirect = await verifier.TryVerifyPresentationAsync(
            presentation, _signingKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.True(asyncDirect.IsValid, asyncDirect.ErrorDetails);
    }

    private static (string Payload, string[] Disclosures) CreateNestedDisclosures(
        string childDisclosure,
        string childDigest)
    {
        var parentJson = "[\"salt-parent\",\"profile\",{\"_sd\":[" +
            JsonSerializer.Serialize(childDigest) + "]}]";
        var parentDisclosure = Base64UrlEncoder.Encode(parentJson);
        var parentDigest = new DigestCalculator().ComputeDigest(parentDisclosure, HashAlgorithm.Sha256);
        var payload = JsonSerializer.Serialize(new { exp = 4102444800L, _sd = new[] { parentDigest } });
        return (payload, [parentDisclosure, childDisclosure]);
    }

    private static async Task AssertRejectedAsync(string presentation)
    {
        var verifier = CreateVerifier();

        var direct = verifier.TryVerifyPresentation(presentation, _signingKey);
        Assert.False(direct.IsValid);
        Assert.Contains(ErrorCode.MalformedDisclosure, direct.Errors);

        var resolved = verifier.TryVerifyPresentation(presentation, ResolveKey);
        Assert.False(resolved.IsValid);
        Assert.Contains(ErrorCode.MalformedDisclosure, resolved.Errors);

        var asyncDirect = await verifier.TryVerifyPresentationAsync(
            presentation, _signingKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(asyncDirect.IsValid);
        Assert.Contains(ErrorCode.MalformedDisclosure, asyncDirect.Errors);

        var asyncResolved = await verifier.TryVerifyPresentationAsync(
            presentation, ResolveKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(asyncResolved.IsValid);
        Assert.Contains(ErrorCode.MalformedDisclosure, asyncResolved.Errors);

        var thrown = Assert.Throws<SdJwtException>(() =>
            verifier.VerifyPresentation(presentation, _signingKey));
        Assert.Equal(ErrorCode.MalformedDisclosure, thrown.ErrorCode);
    }

    private static SdJwtVerifier CreateVerifier() =>
        SdJwtVerifierBuilder.Create().WithExpectedKeyType(VerificationKeyType.Symmetric).Build();

    private static byte[]? ResolveKey(string kid) =>
        kid == "sd-alg-guard" ? _signingKey : null;

    private static string SignPayload(string payloadJson)
    {
        const string header = /*lang=json,strict*/ """{"alg":"HS256","kid":"sd-alg-guard"}""";
        var input = Base64UrlEncoder.Encode(header) + "." + Base64UrlEncoder.Encode(payloadJson);
        var signature = HMACSHA256.HashData(_signingKey, System.Text.Encoding.UTF8.GetBytes(input));
        return input + "." + Base64UrlEncoder.Encode(signature);
    }
}
