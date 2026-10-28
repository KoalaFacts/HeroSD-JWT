using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
using HeroSdJwt.KeyBinding;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;
using System.Text.Json;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Exercises correctly signed issuer JWTs with a holder proof to ensure that
/// a malformed confirmation claim fails through the public verifier contract.
/// </summary>
public class KeyBindingConfirmationShapeTests
{
    private const string AUDIENCE = "https://verifier.example.test";
    private const string NONCE = "verifier-challenge";
    private static readonly byte[] _issuerKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Theory]
    [InlineData("null")]
    [InlineData("true")]
    [InlineData("42")]
    [InlineData("\"not-an-object\"")]
    [InlineData("[]")]
    public async Task Should_RejectSignedIssuerTokenWithNonObjectConfirmation(string confirmationJson)
    {
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var presentation = CreateSignedPresentation(confirmationJson, holder);
        var verifier = CreateVerifier();

        var direct = verifier.TryVerifyPresentation(presentation, _issuerKey);
        Assert.False(direct.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, direct.Errors);

        static byte[]? ResolveIssuerKey(string kid)
        {
            return kid == "issuer-key" ? _issuerKey : null;
        }

        var resolved = verifier.TryVerifyPresentation(presentation, ResolveIssuerKey);
        Assert.False(resolved.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, resolved.Errors);

        // Before the fix, accessing cnf.jwk on a scalar/array leaked
        // InvalidOperationException from the throwing public method.
        var exception = Assert.Throws<SdJwtException>(() =>
            verifier.VerifyPresentation(presentation, _issuerKey));
        Assert.Equal(ErrorCode.InvalidInput, exception.ErrorCode);

        var asyncDirect = await verifier.TryVerifyPresentationAsync(
            presentation, _issuerKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(asyncDirect.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, asyncDirect.Errors);

        var asyncResolved = await verifier.TryVerifyPresentationAsync(
            presentation, ResolveIssuerKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(asyncResolved.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, asyncResolved.Errors);
    }

    [Fact]
    public async Task Should_AcceptWellFormedConfirmationWithValidSignedHolderProof()
    {
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicParameters = holder.ExportParameters(false);
        var confirmationJson = JsonSerializer.Serialize(new
        {
            jwk = new
            {
                kty = "EC",
                crv = "P-256",
                x = Base64UrlEncoder.Encode(publicParameters.Q.X!),
                y = Base64UrlEncoder.Encode(publicParameters.Q.Y!)
            }
        });
        var presentation = CreateSignedPresentation(confirmationJson, holder);
        var verifier = CreateVerifier();

        var result = await verifier.TryVerifyPresentationAsync(
            presentation, _issuerKey, cancellationToken: TestContext.Current.CancellationToken);

        Assert.True(result.IsValid, result.ErrorDetails);
    }

    [Theory]
    [InlineData("\"jwe\":\"encrypted-other-key\"")]
    [InlineData("\"jku\":\"https://keys.example.test/jwks\"")]
    public async Task Should_RejectConfirmationWithMultipleHolderKeyMethods(string extraMethod)
    {
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var point = holder.ExportParameters(false).Q;
        var jwk = JsonSerializer.Serialize(new
        {
            kty = "EC",
            crv = "P-256",
            x = Base64UrlEncoder.Encode(point.X!),
            y = Base64UrlEncoder.Encode(point.Y!)
        });
        var presentation = CreateSignedPresentation($"{{\"jwk\":{jwk},{extraMethod}}}", holder);
        var verifier = CreateVerifier();

        // RFC 7800 permits only one proof-of-possession confirmation method.
        // A correctly signed issuer JWT and holder proof must not override that rule.
        var direct = verifier.TryVerifyPresentation(presentation, _issuerKey);
        Assert.False(direct.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, direct.Errors);

        var resolved = verifier.TryVerifyPresentation(
            presentation, kid => kid == "issuer-key" ? _issuerKey : null);
        Assert.False(resolved.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, resolved.Errors);

        var asyncDirect = await verifier.TryVerifyPresentationAsync(
            presentation, _issuerKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(asyncDirect.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, asyncDirect.Errors);
    }

    [Fact]
    public async Task Should_RejectConfirmationJwkContainingHolderPrivateKey()
    {
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var parameters = holder.ExportParameters(true);
        var confirmationJson = JsonSerializer.Serialize(new
        {
            jwk = new
            {
                kty = "EC",
                crv = "P-256",
                x = Base64UrlEncoder.Encode(parameters.Q.X!),
                y = Base64UrlEncoder.Encode(parameters.Q.Y!),
                d = Base64UrlEncoder.Encode(parameters.D!)
            }
        });
        var presentation = CreateSignedPresentation(confirmationJson, holder);
        var verifier = CreateVerifier();

        // The cnf JWK is public holder-key material, not a place to expose d.
        var direct = verifier.TryVerifyPresentation(presentation, _issuerKey);
        Assert.False(direct.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, direct.Errors);

        var resolved = verifier.TryVerifyPresentation(
            presentation, kid => kid == "issuer-key" ? _issuerKey : null);
        Assert.False(resolved.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, resolved.Errors);

        var asyncDirect = await verifier.TryVerifyPresentationAsync(
            presentation, _issuerKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(asyncDirect.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, asyncDirect.Errors);
    }

    [Fact]
    public void Should_AllowPublicHolderJwkWithOptionalKeyMetadata()
    {
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var point = holder.ExportParameters(false).Q;
        var confirmationJson = JsonSerializer.Serialize(new
        {
            jwk = new
            {
                kty = "EC",
                crv = "P-256",
                x = Base64UrlEncoder.Encode(point.X!),
                y = Base64UrlEncoder.Encode(point.Y!),
                kid = "holder-key-1",
                use = "sig"
            }
        });
        var presentation = CreateSignedPresentation(confirmationJson, holder);

        var result = CreateVerifier().TryVerifyPresentation(presentation, _issuerKey);
        Assert.True(result.IsValid, result.ErrorDetails);
    }

    private static SdJwtVerifier CreateVerifier() =>
        TestHelpers.CreateVerifier(new SdJwtVerificationOptions
        {
            ExpectedKeyType = VerificationKeyType.Symmetric,
            ExpectedAudience = AUDIENCE,
            ExpectedNonce = NONCE,
            RequireKeyBinding = true
        });

    private static string CreateSignedPresentation(string confirmationJson, ECDsa holder)
    {
        var expires = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds();
        var payloadJson = $"{{\"exp\":{expires},\"aud\":\"{AUDIENCE}\",\"_sd\":[],\"cnf\":{confirmationJson}}}";
        const string headerJson = /*lang=json,strict*/ "{\"alg\":\"HS256\",\"kid\":\"issuer-key\"}";
        var signingInput = Base64UrlEncoder.Encode(headerJson) + "." + Base64UrlEncoder.Encode(payloadJson);
        var signature = HMACSHA256.HashData(_issuerKey, System.Text.Encoding.UTF8.GetBytes(signingInput));
        var issuerJwt = signingInput + "." + Base64UrlEncoder.Encode(signature);
        var unsignedHolderPresentation = issuerJwt + "~";
        var sdHash = Base64UrlEncoder.Encode(SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(unsignedHolderPresentation)));
        var holderProof = new KeyBindingGenerator().CreateKeyBindingJwt(
            holder.ExportECPrivateKey(), sdHash, AUDIENCE, NONCE);

        return unsignedHolderPresentation + holderProof;
    }
}
