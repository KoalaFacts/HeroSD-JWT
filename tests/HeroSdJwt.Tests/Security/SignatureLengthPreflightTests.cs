using HeroSdJwt.Encoding;
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
        KeyResolver resolver = _ =>
        {
            wasCalled = true;
            return new byte[64];
        };

        var jwt = CreateJwt(algorithm, invalidSignatureLength, includeKeyId: true);
        Assert.False(new SignatureValidator().VerifyJwtSignature(jwt, resolver));
        Assert.False(wasCalled, "A structurally impossible signature must not trigger external key resolution.");
    }

    [Theory]
    [InlineData("ES256", 63)]
    [InlineData("ES256", 65)]
    [InlineData("ES384", 95)]
    [InlineData("ES384", 97)]
    [InlineData("ES512", 131)]
    [InlineData("ES512", 133)]
    public void Should_RejectImpossibleEcdsaSignatureLength_BeforeImportingKey(
        string algorithm, int invalidSignatureLength)
    {
        // A wrong-curve SPKI normally raises an invalid-input exception after
        // import. The impossible signature must be rejected before that work.
        var wrongCurve = algorithm == "ES256"
            ? ECCurve.NamedCurves.nistP384
            : ECCurve.NamedCurves.nistP256;
        using var key = ECDsa.Create(wrongCurve);
        var jwt = CreateJwt(algorithm, invalidSignatureLength, includeKeyId: false);

        Assert.False(new SignatureValidator().VerifyJwtSignature(
            jwt, key.ExportSubjectPublicKeyInfo()));
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
