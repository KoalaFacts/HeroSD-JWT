using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// RFC 9901 combined presentations contain a JWT followed by zero or more
/// nonempty base64url Disclosures, each separated by '~'. A whitespace-only
/// component is not an absent Disclosure or an absent KB-JWT.
/// </summary>
public class PresentationComponentShapeTests
{
    private static readonly byte[] _signingKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Theory]
    [InlineData("~~")]
    [InlineData("~ ")]
    [InlineData("~\t")]
    [InlineData("~ ~")]
    [InlineData("~\t~")]
    [InlineData("~\u2003~")]
    public async Task Should_RejectEmptyOrWhitespaceOnlyExtraComponents_BeforeResolvingKeys(string suffix)
    {
        var presentation = CreateSignedJwt() + suffix;
        var verifier = CreateVerifier();
        var resolverCalls = 0;
        KeyResolver resolver = keyId =>
        {
            resolverCalls++;
            return keyId == "component-key" ? _signingKey : null;
        };

        var direct = verifier.TryVerifyPresentation(presentation, _signingKey);
        Assert.False(direct.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, direct.Errors);

        var resolved = verifier.TryVerifyPresentation(presentation, resolver);
        Assert.False(resolved.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, resolved.Errors);
        Assert.Equal(0, resolverCalls);

        var exception = Assert.Throws<SdJwtException>(() =>
            verifier.VerifyPresentation(presentation, _signingKey));
        Assert.Equal(ErrorCode.InvalidInput, exception.ErrorCode);

        var asyncDirect = await verifier.TryVerifyPresentationAsync(
            presentation, _signingKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(asyncDirect.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, asyncDirect.Errors);

        var asyncResolved = await verifier.TryVerifyPresentationAsync(
            presentation, resolver, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(asyncResolved.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, asyncResolved.Errors);
        Assert.Equal(0, resolverCalls);
    }

    [Fact]
    public async Task Should_AcceptSingleRequiredTrailingSeparator_WithoutDisclosures()
    {
        var presentation = CreateSignedJwt() + "~";
        var verifier = CreateVerifier();

        var direct = verifier.TryVerifyPresentation(presentation, _signingKey);
        Assert.True(direct.IsValid, direct.ErrorDetails);

        var resolved = verifier.TryVerifyPresentation(presentation, ResolveKey);
        Assert.True(resolved.IsValid, resolved.ErrorDetails);

        var asyncDirect = await verifier.TryVerifyPresentationAsync(
            presentation, _signingKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.True(asyncDirect.IsValid, asyncDirect.ErrorDetails);
    }

    private static byte[]? ResolveKey(string keyId) =>
        keyId == "component-key" ? _signingKey : null;

    private static SdJwtVerifier CreateVerifier() =>
        SdJwtVerifierBuilder.Create().WithExpectedKeyType(VerificationKeyType.Symmetric).Build();

    private static string CreateSignedJwt()
    {
        const string header = /*lang=json,strict*/ "{\"alg\":\"HS256\",\"kid\":\"component-key\"}";
        const string payload = /*lang=json,strict*/ "{\"exp\":4102444800}";
        var signingInput = Base64UrlEncoder.Encode(header) + "." + Base64UrlEncoder.Encode(payload);
        var signature = HMACSHA256.HashData(_signingKey, System.Text.Encoding.UTF8.GetBytes(signingInput));
        return signingInput + "." + Base64UrlEncoder.Encode(signature);
    }
}
