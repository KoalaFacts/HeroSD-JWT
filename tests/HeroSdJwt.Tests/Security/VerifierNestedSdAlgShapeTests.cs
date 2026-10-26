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
/// RFC 9901 only permits _sd_alg at the root of an issuer-signed payload.
/// A correctly signed nested control claim must not be silently accepted.
/// </summary>
public class VerifierNestedSdAlgShapeTests
{
    private static readonly byte[] _signingKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Theory]
    [InlineData("{\"exp\":4102444800,\"profile\":{\"_sd_alg\":\"sha-512\"}}")]
    [InlineData("{\"exp\":4102444800,\"profile\":{\"address\":{\"_sd_alg\":\"sha-256\"}}}")]
    [InlineData("{\"exp\":4102444800,\"roles\":[{\"_sd_alg\":null}]}")]
    public async Task Should_RejectNestedSdAlgInSignedPayload(string payloadJson)
    {
        await AssertRejectedAsync(payloadJson);
    }

    [Theory]
    [InlineData("[\"salt-parent\",\"profile\",{\"_sd_alg\":\"sha-256\",\"display\":\"Alice\"}]")]
    [InlineData("[\"salt-parent\",\"profile\",{\"address\":{\"_sd_alg\":\"sha-512\"}}]")]
    [InlineData("[\"salt-parent\",\"profile\",[{\"_sd_alg\":null}]]")]
    public async Task Should_RejectNestedSdAlgInPresentedDisclosure(string disclosureJson)
    {
        var disclosure = Base64UrlEncoder.Encode(disclosureJson);
        var digest = new DigestCalculator().ComputeDigest(disclosure, HashAlgorithm.Sha256);
        var payload = JsonSerializer.Serialize(new { exp = 4102444800L, _sd = new[] { digest } });

        await AssertRejectedAsync(payload, disclosure);
    }

    [Fact]
    public async Task Should_AcceptTopLevelSdAlgAndOrdinaryNestedClaims()
    {
        const string payload = "{\"exp\":4102444800,\"_sd_alg\":\"sha-256\",\"profile\":{\"name\":\"Alice\",\"roles\":[\"member\"]}}";
        var presentation = SignPayload(payload) + "~";
        var verifier = CreateVerifier();

        var direct = verifier.TryVerifyPresentation(presentation, _signingKey);
        Assert.True(direct.IsValid, direct.ErrorDetails);

        var resolved = verifier.TryVerifyPresentation(presentation, ResolveKey);
        Assert.True(resolved.IsValid, resolved.ErrorDetails);

        var asyncResult = await verifier.TryVerifyPresentationAsync(
            presentation, _signingKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.True(asyncResult.IsValid, asyncResult.ErrorDetails);
    }

    [Fact]
    public async Task Should_AcceptOrdinaryNestedDisclosedObject()
    {
        const string disclosureJson = "[\"salt-parent\",\"profile\",{\"address\":{\"city\":\"Sydney\"}}]";
        var disclosure = Base64UrlEncoder.Encode(disclosureJson);
        var digest = new DigestCalculator().ComputeDigest(disclosure, HashAlgorithm.Sha256);
        var payload = JsonSerializer.Serialize(new { exp = 4102444800L, _sd_alg = "sha-256", _sd = new[] { digest } });
        var presentation = SignPayload(payload) + "~" + disclosure + "~";
        var verifier = CreateVerifier();

        var direct = verifier.TryVerifyPresentation(presentation, _signingKey);
        Assert.True(direct.IsValid, direct.ErrorDetails);

        var asyncResult = await verifier.TryVerifyPresentationAsync(
            presentation, _signingKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.True(asyncResult.IsValid, asyncResult.ErrorDetails);
    }

    private static async Task AssertRejectedAsync(string payloadJson, params string[] disclosures)
    {
        // A valid HMAC signature isolates the payload/disclosure-shape violation.
        var presentation = SignPayload(payloadJson) + "~";
        if (disclosures.Length > 0)
        {
            presentation += string.Join("~", disclosures) + "~";
        }

        var verifier = CreateVerifier();

        var direct = verifier.TryVerifyPresentation(presentation, _signingKey);
        Assert.False(direct.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, direct.Errors);

        var resolved = verifier.TryVerifyPresentation(presentation, ResolveKey);
        Assert.False(resolved.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, resolved.Errors);

        var exception = Assert.Throws<SdJwtException>(() =>
            verifier.VerifyPresentation(presentation, _signingKey));
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

    private static byte[]? ResolveKey(string keyId) =>
        keyId == "nested-sd-alg-key" ? _signingKey : null;

    private static SdJwtVerifier CreateVerifier() =>
        SdJwtVerifierBuilder.Create().WithExpectedKeyType(VerificationKeyType.Symmetric).Build();

    private static string SignPayload(string payloadJson)
    {
        const string header = "{\"alg\":\"HS256\",\"kid\":\"nested-sd-alg-key\"}";
        var input = Base64UrlEncoder.Encode(header) + "." + Base64UrlEncoder.Encode(payloadJson);
        var signature = HMACSHA256.HashData(_signingKey, System.Text.Encoding.UTF8.GetBytes(input));
        return input + "." + Base64UrlEncoder.Encode(signature);
    }
}
