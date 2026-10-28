using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Issuance;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;
using System.Text.Json;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// RFC 9901 reserves the "..." member exclusively for array-element digest placeholders.
/// An authenticated ordinary object member with that name must not be treated as a plain claim.
/// </summary>
public class ReservedArrayPlaceholderPlacementTests
{
    private static readonly byte[] _signingKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Theory]
    [InlineData("\"...\":\"opaque\"")]
    [InlineData("\"profile\":{\"...\":\"opaque\"}")]
    [InlineData("\"records\":[{\"profile\":{\"...\":\"opaque\"}}]")]
    public async Task Should_RejectReservedPlaceholderOutsideArraySlotInSignedPayload(string payloadMember)
    {
        var payload = "{\"exp\":4102444800," + payloadMember + "}";
        await AssertRejectedAsync(SignPayload(payload) + "~");
    }

    [Theory]
    [InlineData(/*lang=json,strict*/ "{\"...\":\"opaque\"}")]
    [InlineData(/*lang=json,strict*/ "{\"address\":{\"...\":\"opaque\"}}")]
    [InlineData(/*lang=json,strict*/ "{\"records\":[{\"profile\":{\"...\":\"opaque\"}}]}")]
    public async Task Should_RejectReservedPlaceholderInsidePresentedObjectDisclosure(string disclosedValue)
    {
        var disclosure = Base64UrlEncoder.Encode("[\"salt\",\"profile\"," + disclosedValue + "]");
        var digest = new DigestCalculator().ComputeDigest(disclosure, HashAlgorithm.Sha256);
        var payload = JsonSerializer.Serialize(new { exp = 4102444800L, _sd = new[] { digest } });

        await AssertRejectedAsync(SignPayload(payload) + "~" + disclosure + "~");
    }

    [Fact]
    public async Task Should_AcceptValidArrayDigestPlaceholderAndOrdinarySimilarMemberName()
    {
        const string disclosedValue = /*lang=json,strict*/ "[\"salt\",\"member\"]";
        var disclosure = Base64UrlEncoder.Encode(disclosedValue);
        var digest = new DigestCalculator().ComputeDigest(disclosure, HashAlgorithm.Sha256);
        var payload = "{\"exp\":4102444800,\"items\":[{\"...\":" +
            JsonSerializer.Serialize(digest) + "}],\"....\":\"ordinary-value\"}";
        var presentation = SignPayload(payload) + "~" + disclosure + "~";
        var verifier = CreateVerifier();

        var direct = verifier.TryVerifyPresentation(presentation, _signingKey);
        Assert.True(direct.IsValid, direct.ErrorDetails);
        Assert.Equal("member", direct.DisclosedClaims["items[0]"].GetString());

        var resolved = verifier.TryVerifyPresentation(presentation, ResolveKey);
        Assert.True(resolved.IsValid, resolved.ErrorDetails);

        var asyncResult = await verifier.TryVerifyPresentationAsync(
            presentation, _signingKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.True(asyncResult.IsValid, asyncResult.ErrorDetails);
    }

    private static async Task AssertRejectedAsync(string presentation)
    {
        var verifier = CreateVerifier();

        var direct = verifier.TryVerifyPresentation(presentation, _signingKey);
        Assert.False(direct.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, direct.Errors);

        var resolved = verifier.TryVerifyPresentation(presentation, ResolveKey);
        Assert.False(resolved.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, resolved.Errors);

        var asyncDirect = await verifier.TryVerifyPresentationAsync(
            presentation, _signingKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(asyncDirect.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, asyncDirect.Errors);

        var asyncResolved = await verifier.TryVerifyPresentationAsync(
            presentation, ResolveKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(asyncResolved.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, asyncResolved.Errors);

        var exception = Assert.Throws<SdJwtException>(() =>
            verifier.VerifyPresentation(presentation, _signingKey));
        Assert.Equal(ErrorCode.InvalidInput, exception.ErrorCode);
    }

    private static SdJwtVerifier CreateVerifier() =>
        SdJwtVerifierBuilder.Create().WithExpectedKeyType(VerificationKeyType.Symmetric).Build();

    private static byte[]? ResolveKey(string keyId) =>
        keyId == "reserved-array-placeholder" ? _signingKey : null;

    private static string SignPayload(string payloadJson)
    {
        const string header = /*lang=json,strict*/ "{\"alg\":\"HS256\",\"kid\":\"reserved-array-placeholder\"}";
        var input = Base64UrlEncoder.Encode(header) + "." + Base64UrlEncoder.Encode(payloadJson);
        var signature = HMACSHA256.HashData(_signingKey, System.Text.Encoding.UTF8.GetBytes(input));
        return input + "." + Base64UrlEncoder.Encode(signature);
    }
}
