using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Signed malformed JWT payloads must be rejected through the public verifier
/// contract, rather than throwing unexpected JSON accessor exceptions.
/// </summary>
public class JwtPayloadShapeTests
{
    private static readonly byte[] _signingKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Theory]
    [InlineData("null")]
    [InlineData("[]")]
    [InlineData("42")]
    [InlineData("\"not-an-object\"")]
    public async Task Should_RejectSignedJwtWithNonObjectPayload(string payloadJson)
    {
        await AssertRejectedAsync(payloadJson);
    }

    [Theory]
    [InlineData("null")]
    [InlineData("[]")]
    [InlineData("{}")]
    [InlineData("42")]
    [InlineData("true")]
    public async Task Should_RejectSignedJwtWithNonStringDisclosureHashAlgorithm(string algorithmJson)
    {
        var expires = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds();
        var payloadJson = $"{{\"exp\":{expires},\"_sd\":[],\"_sd_alg\":{algorithmJson}}}";
        await AssertRejectedAsync(payloadJson);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Should_AcceptValidSignedJwtWithOptionalStringDisclosureHashAlgorithm(bool includeAlgorithm)
    {
        var expires = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds();
        var algorithmMember = includeAlgorithm ? ",\"_sd_alg\":\"sha-256\"" : string.Empty;
        var payloadJson = $"{{\"exp\":{expires},\"_sd\":[]}}";
        payloadJson = payloadJson[..^1] + algorithmMember + "}";
        var presentation = SignPayload(payloadJson) + "~";
        var verifier = CreateVerifier();

        var result = verifier.TryVerifyPresentation(presentation, _signingKey);
        Assert.True(result.IsValid, result.ErrorDetails);
    }

    private static async Task AssertRejectedAsync(string payloadJson)
    {
        var presentation = SignPayload(payloadJson) + "~";
        var verifier = CreateVerifier();

        var direct = verifier.TryVerifyPresentation(presentation, _signingKey);
        Assert.False(direct.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, direct.Errors);

        static byte[]? Resolver(string kid)
        {
            return kid == "key-1" ? _signingKey : null;
        }

        var resolved = verifier.TryVerifyPresentation(presentation, Resolver);
        Assert.False(resolved.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, resolved.Errors);

        // Before this fix, VerifyPresentation could leak InvalidOperationException
        // for a correctly signed non-object payload or non-string _sd_alg.
        var exception = Assert.Throws<SdJwtException>(() =>
            verifier.VerifyPresentation(presentation, _signingKey));
        Assert.Equal(ErrorCode.InvalidInput, exception.ErrorCode);

        var asyncDirect = await verifier.TryVerifyPresentationAsync(
            presentation, _signingKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(asyncDirect.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, asyncDirect.Errors);

        var asyncResolved = await verifier.TryVerifyPresentationAsync(
            presentation, Resolver, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(asyncResolved.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, asyncResolved.Errors);
    }

    private static SdJwtVerifier CreateVerifier()
    {
        return TestHelpers.CreateVerifier(new SdJwtVerificationOptions
        {
            ExpectedKeyType = VerificationKeyType.Symmetric
        });
    }

    private static string SignPayload(string payloadJson)
    {
        const string headerJson = /*lang=json,strict*/ "{\"alg\":\"HS256\",\"kid\":\"key-1\"}";
        var input = Base64UrlEncoder.Encode(headerJson) + "." + Base64UrlEncoder.Encode(payloadJson);
        var digest = HMACSHA256.HashData(_signingKey, System.Text.Encoding.UTF8.GetBytes(input));
        return input + "." + Base64UrlEncoder.Encode(digest);
    }
}
