using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// A fixed-width JOSE signature of the wrong size cannot authenticate a JWT.
/// Reject it before importing a public key or calling an external key resolver.
/// </summary>
public sealed class SignatureLengthPreflightTests
{
    [Theory]
    [InlineData("HS256", 31)]
    [InlineData("HS384", 47)]
    [InlineData("HS512", 63)]
    [InlineData("ES256", 63)]
    [InlineData("ES384", 95)]
    [InlineData("ES512", 131)]
    [InlineData("EdDSA", 63)]
    public void Should_RejectImpossibleSignatureLength_BeforeCallingResolver(
        string algorithm, int invalidSignatureLength)
    {
        var wasCalled = false;
        byte[]? Resolver(string _)
        {
            wasCalled = true;
            return new byte[64];
        }

        var jwt = CreateJwt(algorithm, invalidSignatureLength, includeKeyId: true);
        Assert.False(new SignatureValidator().VerifyJwtSignature(jwt, Resolver));
        Assert.False(wasCalled, "A structurally impossible signature must not trigger external key resolution.");
    }

    [Theory]
    [InlineData("ES256", 63)]
    [InlineData("ES256", 65)]
    [InlineData("ES384", 95)]
    [InlineData("ES384", 97)]
    [InlineData("ES512", 131)]
    [InlineData("ES512", 133)]
    public void Should_PreserveWrongCurveError_WhenEcdsaSignatureLengthIsInvalid(
        string algorithm, int invalidSignatureLength)
    {
        // A wrong-curve SPKI remains a distinct invalid-input configuration
        // failure, even when the supplied signature has an impossible size.
        var wrongCurve = algorithm == "ES256"
            ? ECCurve.NamedCurves.nistP384
            : ECCurve.NamedCurves.nistP256;
        using var key = ECDsa.Create(wrongCurve);
        var jwt = CreateJwt(algorithm, invalidSignatureLength, includeKeyId: false);

        var exception = Assert.Throws<SdJwtException>(() =>
            new SignatureValidator().VerifyJwtSignature(
                jwt, key.ExportSubjectPublicKeyInfo()));
        Assert.Equal(ErrorCode.InvalidInput, exception.ErrorCode);
    }

    [Fact]
    public async Task Should_RejectImpossibleSignatureLength_BeforeHighLevelKeyResolution()
    {
        var resolverCalls = 0;
        byte[]? Resolver(string _)
        {
            resolverCalls++;
            return new byte[64];
        }

        var presentation = CreateJwt("ES256", 63, includeKeyId: true) + "~";
        var verifier = SdJwtVerifierBuilder.Create()
            .WithExpectedKeyType(VerificationKeyType.Asymmetric)
            .Build();

        var result = verifier.TryVerifyPresentation(presentation, Resolver);
        Assert.False(result.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, result.Errors);
        Assert.Equal(0, resolverCalls);

        var asyncResult = await verifier.TryVerifyPresentationAsync(
            presentation, Resolver, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(asyncResult.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, asyncResult.Errors);
        Assert.Equal(0, resolverCalls);
    }

    private static string CreateJwt(string algorithm, int signatureLength, bool includeKeyId)
    {
        var header = includeKeyId
            ? "{\"alg\":\"" + algorithm + "\",\"kid\":\"kid-1\"}"
            : "{\"alg\":\"" + algorithm + "\"}";
        return Base64UrlEncoder.Encode(header) + "." +
            Base64UrlEncoder.Encode("""{"sub":"user"}""") + "." +
            Base64UrlEncoder.Encode(new byte[signatureLength]);
    }
}
