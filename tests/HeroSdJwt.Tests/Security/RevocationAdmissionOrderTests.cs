using HeroSdJwt.Encoding;
using HeroSdJwt.Issuance;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using HeroSdJwt.Verification.Revocation;
using System.Security.Cryptography;
using System.Text.Json;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Revocation is a remote read for some deployments. Rejected presentations
/// must fail read-only validation before accessing that external state.
/// </summary>
public class RevocationAdmissionOrderTests
{
    private const string AUDIENCE = "https://verifier.example.test";
    private const string REVOKED_JTI = "revocation-admission-token";
    private static readonly byte[] _signingKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Theory]
    [InlineData("expired", ErrorCode.TokenExpired)]
    [InlineData("wrong-audience", ErrorCode.InvalidInput)]
    [InlineData("invalid-digest", ErrorCode.DigestMismatch)]
    public async Task Should_RejectInvalidSignedPresentationBeforeRevocationLookup(
        string failure, ErrorCode expectedError)
    {
        using var store = new InMemoryRevocationStore();
        await store.RevokeJtiAsync(
            REVOKED_JTI, DateTimeOffset.UtcNow.AddHours(1),
            TestContext.Current.CancellationToken);
        var verifier = CreateVerifier(store);
        var presentation = CreatePresentation(failure);

        // A revoked JTI is a tripwire: querying revocation too early produces
        // TokenRevoked, masking the actual read-only validation failure.
        var direct = verifier.TryVerifyPresentation(presentation, _signingKey);
        Assert.False(direct.IsValid);
        Assert.Contains(expectedError, direct.Errors);
        Assert.DoesNotContain(ErrorCode.TokenRevoked, direct.Errors);

        var resolved = verifier.TryVerifyPresentation(presentation, ResolveKey);
        Assert.False(resolved.IsValid);
        Assert.Contains(expectedError, resolved.Errors);
        Assert.DoesNotContain(ErrorCode.TokenRevoked, resolved.Errors);

        var asyncDirect = await verifier.TryVerifyPresentationAsync(
            presentation, _signingKey,
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(asyncDirect.IsValid);
        Assert.Contains(expectedError, asyncDirect.Errors);
        Assert.DoesNotContain(ErrorCode.TokenRevoked, asyncDirect.Errors);

        var asyncResolved = await verifier.TryVerifyPresentationAsync(
            presentation, ResolveKey,
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(asyncResolved.IsValid);
        Assert.Contains(expectedError, asyncResolved.Errors);
        Assert.DoesNotContain(ErrorCode.TokenRevoked, asyncResolved.Errors);
    }

    [Fact]
    public async Task Should_ContinueRejectingAuthenticRevokedPresentations()
    {
        using var store = new InMemoryRevocationStore();
        await store.RevokeJtiAsync(
            REVOKED_JTI, DateTimeOffset.UtcNow.AddHours(1),
            TestContext.Current.CancellationToken);
        var verifier = CreateVerifier(store);
        var presentation = CreatePresentation(failure: null);

        var direct = verifier.TryVerifyPresentation(presentation, _signingKey);
        Assert.False(direct.IsValid);
        Assert.Contains(ErrorCode.TokenRevoked, direct.Errors);

        var resolved = await verifier.TryVerifyPresentationAsync(
            presentation, ResolveKey,
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(resolved.IsValid);
        Assert.Contains(ErrorCode.TokenRevoked, resolved.Errors);
    }

    private static SdJwtVerifier CreateVerifier(IRevocationStore store) =>
        TestHelpers.CreateVerifierWithRevocation(
            new SdJwtVerificationOptions
            {
                ExpectedKeyType = VerificationKeyType.Symmetric,
                ExpectedAudience = AUDIENCE
            }, store);

    private static byte[]? ResolveKey(string keyId) =>
        keyId == "revocation-admission-key" ? _signingKey : null;

    private static string CreatePresentation(string? failure)
    {
        var exp = (failure == "expired"
            ? DateTimeOffset.UtcNow.AddHours(-1)
            : DateTimeOffset.UtcNow.AddHours(1)).ToUnixTimeSeconds();
        var actualAudience = failure == "wrong-audience"
            ? "https://other-verifier.example.test" : AUDIENCE;

        var disclosure = Base64UrlEncoder.Encode(
            /*lang=json,strict*/ "[\"salt-presented\",\"email\",\"alice@example.test\"]");
        var otherDisclosure = Base64UrlEncoder.Encode(
            /*lang=json,strict*/ "[\"different-salt\",\"email\",\"alice@example.test\"]");
        string[] digests = failure == "invalid-digest"
            ? [new DigestCalculator().ComputeDigest(otherDisclosure, HashAlgorithm.Sha256)]
            : [];
        var payload = JsonSerializer.Serialize(new
        {
            exp,
            aud = actualAudience,
            jti = REVOKED_JTI,
            sub = "alice",
            _sd = digests
        });

        const string header = /*lang=json,strict*/ "{\"alg\":\"HS256\",\"kid\":\"revocation-admission-key\"}";
        var signedInput = Base64UrlEncoder.Encode(header) + "." + Base64UrlEncoder.Encode(payload);
        var signature = HMACSHA256.HashData(_signingKey, System.Text.Encoding.UTF8.GetBytes(signedInput));
        var jwt = signedInput + "." + Base64UrlEncoder.Encode(signature);
        return failure == "invalid-digest" ? jwt + "~" + disclosure + "~" : jwt + "~";
    }
}
