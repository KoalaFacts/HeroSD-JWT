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
/// RFC 9901 Section 4 prohibits sending the same Disclosure more than once.
/// A repeated Disclosure must not be silently deduplicated during reconstruction.
/// </summary>
public class RepeatedDisclosureTests
{
    private static readonly byte[] _signingKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Should_RejectRepeatedSignedDisclosure(bool arrayElement)
    {
        var (jwt, disclosure) = CreateSignedDisclosure(arrayElement);
        var presentation = jwt + "~" + disclosure + "~" + disclosure + "~";
        var verifier = CreateVerifier();

        var direct = verifier.TryVerifyPresentation(presentation, _signingKey);
        Assert.False(direct.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, direct.Errors);

        static byte[]? ResolveKey(string kid)
        {
            return kid == "repeat-key" ? _signingKey : null;
        }

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

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Should_AcceptSingleSignedDisclosure(bool arrayElement)
    {
        var (jwt, disclosure) = CreateSignedDisclosure(arrayElement);
        var presentation = jwt + "~" + disclosure + "~";
        var verifier = CreateVerifier();

        var direct = verifier.TryVerifyPresentation(presentation, _signingKey);
        Assert.True(direct.IsValid, direct.ErrorDetails);

        var asyncResult = await verifier.TryVerifyPresentationAsync(
            presentation, _signingKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.True(asyncResult.IsValid, asyncResult.ErrorDetails);
    }

    private static (string Jwt, string Disclosure) CreateSignedDisclosure(bool arrayElement)
    {
        var json = arrayElement
            ? /*lang=json,strict*/ "[\"salt-array\",\"member\"]"
            : /*lang=json,strict*/ "[\"salt-object\",\"role\",\"member\"]";
        var disclosure = Base64UrlEncoder.Encode(json);
        var digest = new DigestCalculator().ComputeDigest(disclosure, HashAlgorithm.Sha256);
        var payload = arrayElement
            ? JsonSerializer.Serialize(new
            {
                exp = 4102444800L,
                roles = new[] { new Dictionary<string, string> { ["..."] = digest } }
            })
            : JsonSerializer.Serialize(new
            {
                exp = 4102444800L,
                _sd = new[] { digest }
            });

        const string header = /*lang=json,strict*/ "{\"alg\":\"HS256\",\"kid\":\"repeat-key\"}";
        var input = Base64UrlEncoder.Encode(header) + "." + Base64UrlEncoder.Encode(payload);
        var signature = HMACSHA256.HashData(_signingKey, System.Text.Encoding.UTF8.GetBytes(input));
        return (input + "." + Base64UrlEncoder.Encode(signature), disclosure);
    }

    private static SdJwtVerifier CreateVerifier() =>
        SdJwtVerifierBuilder.Create().WithExpectedKeyType(VerificationKeyType.Symmetric).Build();
}
