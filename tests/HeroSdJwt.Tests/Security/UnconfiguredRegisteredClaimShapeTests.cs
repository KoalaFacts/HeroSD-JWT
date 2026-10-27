using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// RFC 7519 registered claim types must remain well-formed even when the
/// verifier has not configured an issuer or audience matching policy.
/// </summary>
public class UnconfiguredRegisteredClaimShapeTests
{
    private static readonly byte[] _signingKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Theory]
    [InlineData(/*lang=json,strict*/ """{"exp":4102444800,"iss":42}""")]
    [InlineData(/*lang=json,strict*/ """{"exp":4102444800,"iss":null}""")]
    [InlineData(/*lang=json,strict*/ """{"exp":4102444800,"iss":true}""")]
    [InlineData(/*lang=json,strict*/ """{"exp":4102444800,"iss":[]}""")]
    [InlineData(/*lang=json,strict*/ """{"exp":4102444800,"iss":{}}""")]
    [InlineData(/*lang=json,strict*/ """{"exp":4102444800,"aud":42}""")]
    [InlineData(/*lang=json,strict*/ """{"exp":4102444800,"aud":null}""")]
    [InlineData(/*lang=json,strict*/ """{"exp":4102444800,"aud":false}""")]
    [InlineData(/*lang=json,strict*/ """{"exp":4102444800,"aud":{}}""")]
    [InlineData(/*lang=json,strict*/ """{"exp":4102444800,"aud":["service-a",17]}""")]
    [InlineData(/*lang=json,strict*/ """{"exp":4102444800,"aud":[null,"service-a"]}""")]
    [InlineData(/*lang=json,strict*/ """{"exp":4102444800,"aud":[["service-a"]]}""")]
    public async Task Should_RejectMalformedRegisteredClaim_WhenNoIssuerOrAudienceConfigured(string payloadJson)
    {
        var presentation = SignPayload(payloadJson) + "~";
        var verifier = CreateVerifier();

        // Authenticate the exact token first: these regressions concern the
        // registered claim shape, not a failed HMAC or malformed JWS.
        Assert.True(new SignatureValidator().VerifyJwtSignature(presentation[..^1], _signingKey));

        var direct = verifier.TryVerifyPresentation(presentation, _signingKey);
        Assert.False(direct.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, direct.Errors);

        var resolved = verifier.TryVerifyPresentation(presentation, ResolveKey);
        Assert.False(resolved.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, resolved.Errors);

        var thrown = Assert.Throws<SdJwtException>(() =>
            verifier.VerifyPresentation(presentation, _signingKey));
        Assert.Equal(ErrorCode.InvalidInput, thrown.ErrorCode);

        var asyncDirect = await verifier.TryVerifyPresentationAsync(
            presentation, _signingKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(asyncDirect.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, asyncDirect.Errors);

        var asyncResolved = await verifier.TryVerifyPresentationAsync(
            presentation, ResolveKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(asyncResolved.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, asyncResolved.Errors);
    }

    [Theory]
    [InlineData(/*lang=json,strict*/ """{"exp":4102444800}""")]
    [InlineData(/*lang=json,strict*/ """{"exp":4102444800,"iss":"https://issuer.example.test"}""")]
    [InlineData(/*lang=json,strict*/ """{"exp":4102444800,"aud":"service-a"}""")]
    [InlineData(/*lang=json,strict*/ """{"exp":4102444800,"aud":["service-a","service-b"]}""")]
    [InlineData(/*lang=json,strict*/ """{"exp":4102444800,"iss":"https://issuer.example.test","aud":["service-a"]}""")]
    public async Task Should_KeepAcceptingWellFormedOptionalClaims_WithoutMatchingPolicy(string payloadJson)
    {
        var presentation = SignPayload(payloadJson) + "~";
        var verifier = CreateVerifier();

        var direct = verifier.TryVerifyPresentation(presentation, _signingKey);
        Assert.True(direct.IsValid, direct.ErrorDetails);

        var asyncResolved = await verifier.TryVerifyPresentationAsync(
            presentation, ResolveKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.True(asyncResolved.IsValid, asyncResolved.ErrorDetails);
    }

    private static SdJwtVerifier CreateVerifier() =>
        TestHelpers.CreateVerifier(new SdJwtVerificationOptions
        {
            ExpectedKeyType = VerificationKeyType.Symmetric
        });

    private static byte[]? ResolveKey(string keyId) =>
        keyId == "optional-claims-key" ? _signingKey : null;

    private static string SignPayload(string payloadJson)
    {
        const string header = /*lang=json,strict*/ """{"alg":"HS256","kid":"optional-claims-key"}""";
        var input = Base64UrlEncoder.Encode(header) + "." + Base64UrlEncoder.Encode(payloadJson);
        var signature = HMACSHA256.HashData(_signingKey, System.Text.Encoding.UTF8.GetBytes(input));
        return input + "." + Base64UrlEncoder.Encode(signature);
    }
}
