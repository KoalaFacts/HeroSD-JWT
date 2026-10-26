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
/// A signed SD-JWT must not authenticate ambiguous nested objects. JSON
/// consumers disagree about which duplicate property wins, even when all
/// bytes carry a valid issuer signature.
/// </summary>
public class NestedJsonMemberSecurityTests
{
    private static readonly byte[] _issuerKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Theory]
    [InlineData("\"profile\":{\"role\":\"reader\",\"role\":\"admin\"}")]
    [InlineData("\"profile\":{\"role\":\"reader\",\"\\u0072ole\":\"admin\"}")]
    [InlineData("\"roles\":[{\"level\":1,\"level\":2}]")]
    [InlineData("\"profile\":{\"_sd\":[],\"_sd\":[]}")]
    [InlineData("\"profile\":{\"name\":\"Alice\",\"address\":{\"city\":\"Sydney\",\"city\":\"Melbourne\"}}")]
    public async Task Should_RejectAmbiguousNestedNamesInSignedPayload(string nestedProperty)
    {
        var payload = "{\"exp\":4102444800,\"_sd_alg\":\"sha-256\"," + nestedProperty + "}";
        await AssertRejectedAsync(payload);
    }

    [Theory]
    [InlineData("[\"salt\",\"profile\",{\"role\":\"reader\",\"role\":\"admin\"}]")]
    [InlineData("[\"salt\",\"profile\",{\"role\":\"reader\",\"\\u0072ole\":\"admin\"}]")]
    [InlineData("[\"salt\",\"profile\",{\"roles\":[{\"level\":1,\"level\":2}]}]")]
    [InlineData("[\"salt\",\"profile\",{\"_sd\":[],\"_sd\":[]}]")]
    public async Task Should_RejectAmbiguousNestedNamesInPresentedDisclosure(string disclosureJson)
    {
        var disclosure = Base64UrlEncoder.Encode(disclosureJson);
        var digest = new DigestCalculator().ComputeDigest(disclosure, HashAlgorithm.Sha256);
        var payload = JsonSerializer.Serialize(new
        {
            exp = 4102444800L,
            _sd_alg = "sha-256",
            _sd = new[] { digest }
        });

        await AssertRejectedAsync(payload, disclosure);
    }

    [Fact]
    public async Task Should_AcceptUniqueNestedNamesInSignedPayloadAndDisclosure()
    {
        const string disclosureJson = "[\"salt\",\"profile\",{\"address\":{\"city\":\"Sydney\",\"state\":\"NSW\"}}]";
        var disclosure = Base64UrlEncoder.Encode(disclosureJson);
        var digest = new DigestCalculator().ComputeDigest(disclosure, HashAlgorithm.Sha256);
        var payload = JsonSerializer.Serialize(new
        {
            exp = 4102444800L,
            _sd_alg = "sha-256",
            settings = new { role = "reader", enabled = true },
            _sd = new[] { digest }
        });
        var presentation = SignPayload(payload) + "~" + disclosure + "~";
        var verifier = CreateVerifier();

        var direct = verifier.TryVerifyPresentation(presentation, _issuerKey);
        Assert.True(direct.IsValid, direct.ErrorDetails);

        var resolved = verifier.TryVerifyPresentation(presentation, ResolveKey);
        Assert.True(resolved.IsValid, resolved.ErrorDetails);

        var asyncDirect = await verifier.TryVerifyPresentationAsync(
            presentation, _issuerKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.True(asyncDirect.IsValid, asyncDirect.ErrorDetails);
    }

    private static async Task AssertRejectedAsync(string payloadJson, params string[] disclosures)
    {
        var jwt = SignPayload(payloadJson);
        Assert.True(new SignatureValidator().VerifyJwtSignature(jwt, _issuerKey));

        var presentation = jwt + "~";
        if (disclosures.Length > 0)
        {
            presentation += string.Join("~", disclosures) + "~";
        }

        var verifier = CreateVerifier();

        var direct = verifier.TryVerifyPresentation(presentation, _issuerKey);
        Assert.False(direct.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, direct.Errors);

        var resolved = verifier.TryVerifyPresentation(presentation, ResolveKey);
        Assert.False(resolved.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, resolved.Errors);

        var asyncDirect = await verifier.TryVerifyPresentationAsync(
            presentation, _issuerKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(asyncDirect.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, asyncDirect.Errors);

        var asyncResolved = await verifier.TryVerifyPresentationAsync(
            presentation, ResolveKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(asyncResolved.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, asyncResolved.Errors);

        var exception = Assert.Throws<SdJwtException>(() =>
            verifier.VerifyPresentation(presentation, _issuerKey));
        Assert.Equal(ErrorCode.InvalidInput, exception.ErrorCode);
    }

    private static SdJwtVerifier CreateVerifier() =>
        SdJwtVerifierBuilder.Create().WithExpectedKeyType(VerificationKeyType.Symmetric).Build();

    private static byte[]? ResolveKey(string keyId) =>
        keyId == "nested-json-key" ? _issuerKey : null;

    private static string SignPayload(string payloadJson)
    {
        const string header = /*lang=json,strict*/ "{\"alg\":\"HS256\",\"kid\":\"nested-json-key\"}";
        var input = Base64UrlEncoder.Encode(header) + "." + Base64UrlEncoder.Encode(payloadJson);
        var signature = HMACSHA256.HashData(_issuerKey, System.Text.Encoding.UTF8.GetBytes(input));
        return input + "." + Base64UrlEncoder.Encode(signature);
    }
}
