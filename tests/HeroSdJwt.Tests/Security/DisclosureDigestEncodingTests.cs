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
/// RFC 9901 Section 4.2.3 requires canonical base64url-encoded digest bytes.
/// Invalid unpresented decoys must not evade verification.
/// </summary>
public class DisclosureDigestEncodingTests
{
    private static readonly byte[] _signingKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Theory]
    [InlineData("sha-256", 42, 'A')]
    [InlineData("sha-256", 44, 'A')]
    [InlineData("sha-256", 43, 'B')]
    [InlineData("sha-256", 43, '=')]
    [InlineData("sha-256", 43, '!')]
    [InlineData("sha-384", 63, 'A')]
    [InlineData("sha-384", 65, 'A')]
    [InlineData("sha-384", 64, '/')]
    [InlineData("sha-512", 85, 'A')]
    [InlineData("sha-512", 87, 'A')]
    [InlineData("sha-512", 86, 'B')]
    [InlineData("sha-512", 86, '+')]
    public async Task Should_RejectMalformedUnpresentedDigestsInObjectAndArrayReferences(
        string hashName, int length, char finalCharacter)
    {
        var invalidDigest = new string('A', length - 1) + finalCharacter;
        var payloads = new[]
        {
            JsonSerializer.Serialize(new { exp = 4102444800L, _sd_alg = hashName, _sd = new[] { invalidDigest } }),
            JsonSerializer.Serialize(new { exp = 4102444800L, _sd_alg = hashName, profile = new { _sd = new[] { invalidDigest } } }),
            JsonSerializer.Serialize(new
            {
                exp = 4102444800L,
                _sd_alg = hashName,
                roles = new[] { new Dictionary<string, string> { ["..."] = invalidDigest } }
            })
        };

        foreach (var payload in payloads)
        {
            await AssertRejectedAsync(payload);
        }
    }

    [Theory]
    [InlineData("sha-256", HashAlgorithm.Sha256, 43, 'B')]
    [InlineData("sha-384", HashAlgorithm.Sha384, 64, '/')]
    [InlineData("sha-512", HashAlgorithm.Sha512, 86, 'B')]
    public async Task Should_RejectMalformedNestedDigestInPresentedDisclosure(
        string hashName, HashAlgorithm hashAlgorithm, int length, char finalCharacter)
    {
        var invalidDigest = new string('A', length - 1) + finalCharacter;
        var disclosureJson = JsonSerializer.Serialize(new object[]
        {
            "parent-salt",
            "profile",
            new { _sd = new[] { invalidDigest } }
        });
        var disclosure = Base64UrlEncoder.Encode(disclosureJson);
        var parentDigest = new DigestCalculator().ComputeDigest(disclosure, hashAlgorithm);
        var payload = JsonSerializer.Serialize(new { exp = 4102444800L, _sd_alg = hashName, _sd = new[] { parentDigest } });

        await AssertRejectedAsync(payload, ErrorCode.InvalidInput, disclosure);
    }

    [Theory]
    [InlineData("SHA-256")]
    [InlineData("Sha-384")]
    [InlineData("SHA-512")]
    public async Task Should_RejectNonCanonicalCaseOfSdHashAlgorithm(string hashName)
    {
        var payload = JsonSerializer.Serialize(new { exp = 4102444800L, _sd_alg = hashName });
        await AssertRejectedAsync(payload, ErrorCode.UnsupportedAlgorithm);
    }

    [Theory]
    [InlineData("sha-256", HashAlgorithm.Sha256)]
    [InlineData("sha-384", HashAlgorithm.Sha384)]
    [InlineData("sha-512", HashAlgorithm.Sha512)]
    public async Task Should_AcceptCanonicalDisclosuresAndUndisclosedDecoyForSupportedHashes(
        string hashName, HashAlgorithm hashAlgorithm)
    {
        var objectDisclosure = Base64UrlEncoder.Encode(/*lang=json,strict*/ "[\"salt-object\",\"name\",\"Alice\"]");
        var arrayDisclosure = Base64UrlEncoder.Encode(/*lang=json,strict*/ "[\"salt-array\",\"member\"]");
        var calculator = new DigestCalculator();
        var objectDigest = calculator.ComputeDigest(objectDisclosure, hashAlgorithm);
        var arrayDigest = calculator.ComputeDigest(arrayDisclosure, hashAlgorithm);
        var decoyDigest = new DecoyDigestGenerator(calculator).GenerateDecoyDigests(1, hashAlgorithm)[0];
        var payload = JsonSerializer.Serialize(new
        {
            exp = 4102444800L,
            _sd_alg = hashName,
            _sd = new[] { objectDigest, decoyDigest },
            roles = new[] { new Dictionary<string, string> { ["..."] = arrayDigest } }
        });
        var presentation = SignPayload(payload) + "~" + objectDisclosure + "~" + arrayDisclosure + "~";
        var verifier = CreateVerifier();

        var direct = verifier.TryVerifyPresentation(presentation, _signingKey);
        Assert.True(direct.IsValid, direct.ErrorDetails);
        Assert.Equal("Alice", direct.DisclosedClaims["name"].GetString());
        Assert.Equal("member", direct.DisclosedClaims["roles[0]"].GetString());

        var resolved = verifier.TryVerifyPresentation(presentation, ResolveKey);
        Assert.True(resolved.IsValid, resolved.ErrorDetails);

        var asyncResult = await verifier.TryVerifyPresentationAsync(
            presentation, _signingKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.True(asyncResult.IsValid, asyncResult.ErrorDetails);
    }

    [Theory]
    [InlineData("sha-256", 'E')]
    [InlineData("sha-512", 'Q')]
    public async Task Should_AcceptValidNonzeroTerminalSextetsInUnpresentedDigests(
        string hashName, char finalCharacter)
    {
        // SHA-256's final 2 padding bits are zero for 'E' (sextet 4).
        // SHA-512's final 4 padding bits are zero for 'Q' (sextet 16).
        // Both are canonical although the final digit is not 'A'.
        var length = hashName == "sha-256" ? 43 : 86;
        var digest = new string('A', length - 1) + finalCharacter;
        var payloads = new[]
        {
            JsonSerializer.Serialize(new { exp = 4102444800L, _sd_alg = hashName, _sd = new[] { digest } }),
            JsonSerializer.Serialize(new
            {
                exp = 4102444800L,
                _sd_alg = hashName,
                roles = new[] { new Dictionary<string, string> { ["..."] = digest } }
            })
        };

        foreach (var payload in payloads)
        {
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
    }

    private static async Task AssertRejectedAsync(
        string payloadJson, ErrorCode expectedError = ErrorCode.InvalidInput, params string[] disclosures)
    {
        var presentation = SignPayload(payloadJson) + "~";
        if (disclosures.Length > 0)
        {
            presentation += string.Join("~", disclosures) + "~";
        }

        var verifier = CreateVerifier();

        var direct = verifier.TryVerifyPresentation(presentation, _signingKey);
        Assert.False(direct.IsValid);
        Assert.Contains(expectedError, direct.Errors);

        var resolved = verifier.TryVerifyPresentation(presentation, ResolveKey);
        Assert.False(resolved.IsValid);
        Assert.Contains(expectedError, resolved.Errors);

        var exception = Assert.Throws<SdJwtException>(() =>
            verifier.VerifyPresentation(presentation, _signingKey));
        Assert.Equal(expectedError, exception.ErrorCode);

        var asyncDirect = await verifier.TryVerifyPresentationAsync(
            presentation, _signingKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(asyncDirect.IsValid);
        Assert.Contains(expectedError, asyncDirect.Errors);

        var asyncResolved = await verifier.TryVerifyPresentationAsync(
            presentation, ResolveKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(asyncResolved.IsValid);
        Assert.Contains(expectedError, asyncResolved.Errors);
    }

    private static byte[]? ResolveKey(string kid) =>
        kid == "digest-encoding-test-key" ? _signingKey : null;

    private static SdJwtVerifier CreateVerifier() =>
        SdJwtVerifierBuilder.Create().WithExpectedKeyType(VerificationKeyType.Symmetric).Build();

    private static string SignPayload(string payloadJson)
    {
        const string headerJson = /*lang=json,strict*/ "{\"alg\":\"HS256\",\"kid\":\"digest-encoding-test-key\"}";
        var input = Base64UrlEncoder.Encode(headerJson) + "." + Base64UrlEncoder.Encode(payloadJson);
        var signature = HMACSHA256.HashData(_signingKey, System.Text.Encoding.UTF8.GetBytes(input));
        return input + "." + Base64UrlEncoder.Encode(signature);
    }
}
