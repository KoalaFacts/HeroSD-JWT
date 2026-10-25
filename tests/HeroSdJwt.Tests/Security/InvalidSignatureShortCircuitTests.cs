using HeroSdJwt.Cryptography;
using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
using HeroSdJwt.KeyBinding;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// A failed issuer signature must stop verification before any untrusted claims
/// are interpreted or application-provided claim validators are invoked.
/// </summary>
public class InvalidSignatureShortCircuitTests
{
    private static readonly byte[] _signingKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Should_NotInspectClaims_WhenIssuerSignatureIsInvalid(bool useResolver)
    {
        var claims = new CountingClaimValidator();
        var verifier = CreateVerifier(claims);
        var presentation = CreatePresentation(invalidSignature: true);

        var result = useResolver
            ? verifier.TryVerifyPresentation(presentation, ResolveKey)
            : verifier.TryVerifyPresentation(presentation, _signingKey);

        Assert.False(result.IsValid);
        Assert.Contains(ErrorCode.InvalidSignature, result.Errors);
        Assert.Equal(0, claims.CallCount);

        var asyncResult = useResolver
            ? await verifier.TryVerifyPresentationAsync(
                presentation, ResolveKey, cancellationToken: TestContext.Current.CancellationToken)
            : await verifier.TryVerifyPresentationAsync(
                presentation, _signingKey, cancellationToken: TestContext.Current.CancellationToken);

        Assert.False(asyncResult.IsValid);
        Assert.Contains(ErrorCode.InvalidSignature, asyncResult.Errors);
        Assert.Equal(0, claims.CallCount);

        var exception = useResolver
            ? Assert.Throws<SdJwtException>(() => verifier.VerifyPresentation(presentation, ResolveKey))
            : Assert.Throws<SdJwtException>(() => verifier.VerifyPresentation(presentation, _signingKey));

        Assert.Equal(ErrorCode.InvalidSignature, exception.ErrorCode);
        Assert.Equal(0, claims.CallCount);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Should_ContinueValidatingClaims_WhenIssuerSignatureIsValid(bool useResolver)
    {
        var claims = new CountingClaimValidator();
        var verifier = CreateVerifier(claims);
        var presentation = CreatePresentation(invalidSignature: false);

        var result = useResolver
            ? await verifier.TryVerifyPresentationAsync(
                presentation, ResolveKey, cancellationToken: TestContext.Current.CancellationToken)
            : await verifier.TryVerifyPresentationAsync(
                presentation, _signingKey, cancellationToken: TestContext.Current.CancellationToken);

        Assert.True(result.IsValid, result.ErrorDetails);
        Assert.Equal(3, claims.CallCount);
    }

    private static byte[]? ResolveKey(string keyId) =>
        keyId == "signature-gate" ? _signingKey : null;

    private static SdJwtVerifier CreateVerifier(IClaimValidator claimValidator) =>
        new(
            new SdJwtVerificationOptions { ExpectedKeyType = VerificationKeyType.Symmetric },
            new EcPublicKeyConverter(),
            new SignatureValidator(),
            new DigestValidator(),
            new KeyBindingValidator(),
            claimValidator);

    private static string CreatePresentation(bool invalidSignature)
    {
        const string header = /*lang=json,strict*/ "{\"alg\":\"HS256\",\"kid\":\"signature-gate\"}";
        const string payload = /*lang=json,strict*/ "{\"exp\":4102444800,\"iss\":\"issuer\"}";
        var signingInput = Base64UrlEncoder.Encode(header) + "." + Base64UrlEncoder.Encode(payload);
        var signature = HMACSHA256.HashData(_signingKey, Encoding.UTF8.GetBytes(signingInput));
        if (invalidSignature)
        {
            signature[0] ^= 1;
        }

        return signingInput + "." + Base64UrlEncoder.Encode(signature) + "~";
    }

    private sealed class CountingClaimValidator : IClaimValidator
    {
        public int CallCount { get; private set; }

        public bool ValidateTemporalClaims(
            JsonElement payload,
            SdJwtVerificationOptions options,
            DateTimeOffset? currentTime = null)
        {
            CallCount++;
            return true;
        }

        public bool ValidateIssuer(JsonElement payload, string? expectedIssuer)
        {
            CallCount++;
            return true;
        }

        public bool ValidateAudience(JsonElement payload, IReadOnlyCollection<string>? expectedAudiences)
        {
            CallCount++;
            return true;
        }
    }
}
