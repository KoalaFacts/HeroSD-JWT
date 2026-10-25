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
    private static readonly byte[] _signingKey = [.. Enumerable.Range(1, 32).Select(index => (byte)index)];

    [Fact]
    public async Task Should_RejectExcessEmptyDisclosureSlots_WithoutBypassingDisclosureLimit()
    {
        var jwt = CreateSignedJwt();
        var oversizedComponents = jwt + new string('~', Constants.MAX_DISCLOSURES + 2);
        var verifier = CreateVerifier();

        var direct = verifier.TryVerifyPresentation(oversizedComponents, _signingKey);
        Assert.False(direct.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, direct.Errors);

        var resolved = verifier.TryVerifyPresentation(oversizedComponents, ResolveKey);
        Assert.False(resolved.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, resolved.Errors);

        var exception = Assert.Throws<SdJwtException>(() =>
            verifier.VerifyPresentation(oversizedComponents, _signingKey));
        Assert.Equal(ErrorCode.InvalidInput, exception.ErrorCode);

        var asyncDirect = await verifier.TryVerifyPresentationAsync(
            oversizedComponents, _signingKey, cancellationToken: TestContext.Current.CancellationToken);
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

        var direct = verifier.TryVerifyPresentation(presentation, _signingKey);
        Assert.True(direct.IsValid, direct.ErrorDetails);

        var resolved = verifier.TryVerifyPresentation(presentation, ResolveKey);
        Assert.True(resolved.IsValid, resolved.ErrorDetails);

        var asyncDirect = await verifier.TryVerifyPresentationAsync(
            presentation, _signingKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.True(asyncDirect.IsValid, asyncDirect.ErrorDetails);
    }

    private static byte[]? ResolveKey(string keyId) =>
        keyId == "separator-limit-key" ? _signingKey : null;

    private static SdJwtVerifier CreateVerifier() =>
        SdJwtVerifierBuilder.Create().WithExpectedKeyType(VerificationKeyType.Symmetric).Build();

    private static string CreateSignedJwt()
    {
        const string header = /*lang=json,strict*/ "{\"alg\":\"HS256\",\"kid\":\"separator-limit-key\"}";
        const string payload = /*lang=json,strict*/ "{\"exp\":4102444800}";
        var signingInput = Base64UrlEncoder.Encode(header) + "." + Base64UrlEncoder.Encode(payload);
        var signature = HMACSHA256.HashData(_signingKey, System.Text.Encoding.UTF8.GetBytes(signingInput));
        return signingInput + "." + Base64UrlEncoder.Encode(signature);
    }
}
