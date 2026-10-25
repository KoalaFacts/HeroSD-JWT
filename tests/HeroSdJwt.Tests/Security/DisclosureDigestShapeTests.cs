using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Issuance;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// RFC 9901 requires every digest reference to occur only once, even when no
/// corresponding Disclosure is presented. Malformed _sd arrays must not be ignored.
/// </summary>
public class DisclosureDigestShapeTests
{
    private static readonly byte[] _signingKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Should_RejectRepeatedObjectDigestInSignedPayload(bool nested)
    {
        var digest = DisclosureDigest("[\"salt-a\",\"email\",\"alice@example.test\"]");
        var quoted = JsonSerializer.Serialize(digest);
        var payload = nested
            ? $"{{\"exp\":4102444800,\"_sd\":[{quoted}],\"profile\":{{\"_sd\":[{quoted}]}}}}"
            : $"{{\"exp\":4102444800,\"_sd\":[{quoted},{quoted}]}}";

        await AssertRejectedAsync(payload);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Should_RejectRepeatedDigestAcrossArrayReferences(bool acrossObjectAndArray)
    {
        var digest = DisclosureDigest("[\"salt-b\",\"role\",\"member\"]");
        var quoted = JsonSerializer.Serialize(digest);
        var payload = acrossObjectAndArray
            ? $"{{\"exp\":4102444800,\"_sd\":[{quoted}],\"items\":[{{\"...\":{quoted}}}]}}"
            : $"{{\"exp\":4102444800,\"items\":[{{\"...\":{quoted}}},{{\"...\":{quoted}}}]}}";

        await AssertRejectedAsync(payload);
    }

    [Theory]
    [InlineData("null")]
    [InlineData("42")]
    [InlineData("\"not-an-array\"")]
    [InlineData("{}")]
    [InlineData("[null]")]
    [InlineData("[false]")]
    [InlineData("[42]")]
    [InlineData("[{}]")]
    [InlineData("[\"valid-digest\",null]")]
    public async Task Should_RejectMalformedSignedDisclosureDigestArray(string invalidSd)
    {
        await AssertRejectedAsync($"{{\"exp\":4102444800,\"_sd\":{invalidSd}}}");
    }

    [Fact]
    public async Task Should_AcceptDistinctSignedDisclosureReferences()
    {
        const string firstJson = "[\"salt-c\",\"email\",\"alice@example.test\"]";
        const string secondJson = "[\"salt-d\",\"name\",\"Alice\"]";
        var firstDisclosure = Base64UrlEncoder.Encode(firstJson);
        var secondDisclosure = Base64UrlEncoder.Encode(secondJson);
        var firstDigest = DisclosureDigest(firstJson);
        var secondDigest = DisclosureDigest(secondJson);
        var payload = JsonSerializer.Serialize(new
        {
            exp = 4102444800L,
            _sd = new[] { firstDigest, secondDigest }
        });
        var presentation = SignPayload(payload) + "~" + firstDisclosure + "~" + secondDisclosure + "~";
        var verifier = CreateVerifier();

        var direct = verifier.TryVerifyPresentation(presentation, _signingKey);
        Assert.True(direct.IsValid, direct.ErrorDetails);
        Assert.Equal("alice@example.test", direct.DisclosedClaims["email"].GetString());
        Assert.Equal("Alice", direct.DisclosedClaims["name"].GetString());

        var asyncResult = await verifier.TryVerifyPresentationAsync(
            presentation, _signingKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.True(asyncResult.IsValid, asyncResult.ErrorDetails);
    }

    [Fact]
    public void Should_AcceptDistinctUnpresentedDecoyDigests()
    {
        var first = DisclosureDigest("[\"decoy-a\",\"unpresented-a\",1]");
        var second = DisclosureDigest("[\"decoy-b\",\"unpresented-b\",2]");
        var payload = JsonSerializer.Serialize(new { exp = 4102444800L, _sd = new[] { first, second } });
        var result = CreateVerifier().TryVerifyPresentation(SignPayload(payload) + "~", _signingKey);

        Assert.True(result.IsValid, result.ErrorDetails);
    }

    private static async Task AssertRejectedAsync(string payloadJson)
    {
        // This JWT is correctly HMAC-signed. Rejection is due to the digest
        // structure, not a bad signature or an unrecognized verification key.
        var presentation = SignPayload(payloadJson) + "~";
        var verifier = CreateVerifier();

        var direct = verifier.TryVerifyPresentation(presentation, _signingKey);
        Assert.False(direct.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, direct.Errors);

        static byte[]? ResolveKey(string kid) => kid == "digest-test-key" ? _signingKey : null;

        var resolved = verifier.TryVerifyPresentation(presentation, ResolveKey);
        Assert.False(resolved.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, resolved.Errors);

        var exception = Assert.Throws<SdJwtException>(() => verifier.VerifyPresentation(presentation, _signingKey));
        Assert.Equal(ErrorCode.InvalidInput, exception.ErrorCode);

        var asyncDirect = await verifier.TryVerifyPresentationAsync(
            presentation, _signingKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(asyncDirect.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, asyncDirect.Errors);

        var asyncResolved = await verifier.TryVerifyPresentationAsync(
            presentation, ResolveKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(asyncResolved.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, asyncResolved.Errors);
    }

    private static SdJwtVerifier CreateVerifier() =>
        SdJwtVerifierBuilder.Create().WithExpectedKeyType(VerificationKeyType.Symmetric).Build();

    private static string DisclosureDigest(string disclosureJson) =>
        new DigestCalculator().ComputeDigest(Base64UrlEncoder.Encode(disclosureJson), HashAlgorithm.Sha256);

    private static string SignPayload(string payloadJson)
    {
        const string headerJson = /*lang=json,strict*/ "{\"alg\":\"HS256\",\"kid\":\"digest-test-key\"}";
        var input = Base64UrlEncoder.Encode(headerJson) + "." + Base64UrlEncoder.Encode(payloadJson);
        var signature = HMACSHA256.HashData(_signingKey, Encoding.UTF8.GetBytes(input));
        return input + "." + Base64UrlEncoder.Encode(signature);
    }
}
