using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// The presentation has an existing 100-Disclosure limit. Empty components
/// must not bypass it and cause a large unbounded Split allocation.
/// </summary>
public class PresentationSeparatorLimitTests
{
    private static readonly byte[] SigningKey = [.. Enumerable.Range(1, 32).Select(index => (byte)index)];

    [Fact]
    public async Task Should_RejectExcessEmptyDisclosureSlots_WithoutBypassingDisclosureLimit()
    {
        var jwt = CreateSignedJwt();
        var oversizedComponents = jwt + new string('~', Constants.MAX_DISCLOSURES + 2);
        var verifier = CreateVerifier();

        var direct = verifier.TryVerifyPresentation(oversizedComponents, SigningKey);
        Assert.False(direct.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, direct.Errors);

        var resolved = verifier.TryVerifyPresentation(oversizedComponents, ResolveKey);
        Assert.False(resolved.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, resolved.Errors);

        var exception = Assert.Throws<SdJwtException>(() =>
            verifier.VerifyPresentation(oversizedComponents, SigningKey));
        Assert.Equal(ErrorCode.InvalidInput, exception.ErrorCode);

        var asyncDirect = await verifier.TryVerifyPresentationAsync(
            oversizedComponents, SigningKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(asyncDirect.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, asyncDirect.Errors);

        var asyncResolved = await verifier.TryVerifyPresentationAsync(
            oversizedComponents, ResolveKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(asyncResolved.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, asyncResolved.Errors);
    }

    [Fact]
    public async Task Should_AcceptValidSignedPresentation_WithoutDisclosures()
    {
        var presentation = CreateSignedJwt() + "~";
        var verifier = CreateVerifier();

        var direct = verifier.TryVerifyPresentation(presentation, SigningKey);
        Assert.True(direct.IsValid, direct.ErrorDetails);

        var resolved = verifier.TryVerifyPresentation(presentation, ResolveKey);
        Assert.True(resolved.IsValid, resolved.ErrorDetails);

        var asyncDirect = await verifier.TryVerifyPresentationAsync(
            presentation, SigningKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.True(asyncDirect.IsValid, asyncDirect.ErrorDetails);
    }

    private static byte[]? ResolveKey(string keyId) =>
        keyId == "separator-limit-key" ? SigningKey : null;

    private static SdJwtVerifier CreateVerifier() =>
        SdJwtVerifierBuilder.Create().WithExpectedKeyType(VerificationKeyType.Symmetric).Build();

    private static string CreateSignedJwt()
    {
        const string header = /*lang=json,strict*/ "{\"alg\":\"HS256\",\"kid\":\"separator-limit-key\"}";
        const string payload = /*lang=json,strict*/ "{\"exp\":4102444800}";
        var signingInput = Base64UrlEncoder.Encode(header) + "." + Base64UrlEncoder.Encode(payload);
        var signature = HMACSHA256.HashData(SigningKey, System.Text.Encoding.UTF8.GetBytes(signingInput));
        return signingInput + "." + Base64UrlEncoder.Encode(signature);
    }
}
