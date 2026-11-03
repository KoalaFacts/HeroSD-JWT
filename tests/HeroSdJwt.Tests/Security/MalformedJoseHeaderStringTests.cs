using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
using HeroSdJwt.KeyBinding;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Signed JOSE registered string parameters must contain valid Unicode even
/// when a caller verifies with a direct key or ignores optional metadata.
/// </summary>
public class MalformedJoseHeaderStringTests
{
    private static readonly byte[] _issuerKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Theory]
    [InlineData("typ")]
    [InlineData("cty")]
    [InlineData("kid")]
    public async Task Should_RejectMalformedUnicodeInSignedIssuerHeader(string parameter)
    {
        var header = parameter == "typ"
            ? "{\"alg\":\"HS256\",\"typ\":\"\\uD800\"}"
            : "{\"alg\":\"HS256\",\"typ\":\"JWT\",\"" + parameter + "\":\"\\uD800\"}";
        var jwt = SignIssuer(header);

        // Prove that rejection is of a genuinely authenticated token, not a
        // signature failure: every mutation has the correct MAC.
        var parts = jwt.Split('.');
        var input = System.Text.Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
        Assert.Equal(Base64UrlEncoder.Encode(HMACSHA256.HashData(_issuerKey, input)), parts[2]);

        var exception = Assert.Throws<SdJwtException>(() =>
            new SignatureValidator().VerifyJwtSignature(jwt, _issuerKey));
        Assert.Equal(ErrorCode.InvalidInput, exception.ErrorCode);

        var verifier = TestHelpers.CreateVerifier(new SdJwtVerificationOptions
        {
            ExpectedKeyType = VerificationKeyType.Symmetric
        });
        var result = verifier.TryVerifyPresentation(jwt + "~", _issuerKey);
        Assert.False(result.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, result.Errors);

        var asyncResult = await verifier.TryVerifyPresentationAsync(
            jwt + "~", _issuerKey, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(asyncResult.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, asyncResult.Errors);
    }

    [Theory]
    [InlineData("cty")]
    [InlineData("kid")]
    public void Should_RejectMalformedUnicodeInSignedHolderHeader(string parameter)
    {
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var header = "{\"alg\":\"ES256\",\"typ\":\"kb+jwt\",\"" + parameter + "\":\"\\uD800\"}";
        var jwt = SignHolder(holder, header);
        Assert.False(new KeyBindingValidator().ValidateKeyBinding(
            jwt, holder.ExportSubjectPublicKeyInfo(), "hash", "audience", "nonce"));
    }

    [Fact]
    public void Should_AcceptValidEscapedUnicodeInOptionalJoseStrings()
    {
        const string issuerHeader = "{\"alg\":\"HS256\",\"typ\":\"JWT\",\"cty\":\"\\uD83D\\uDE00\",\"kid\":\"\\uD83D\\uDE00\"}";
        Assert.True(new SignatureValidator().VerifyJwtSignature(SignIssuer(issuerHeader), _issuerKey));

        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        const string holderHeader = "{\"alg\":\"ES256\",\"typ\":\"kb+jwt\",\"cty\":\"\\uD83D\\uDE00\",\"kid\":\"\\uD83D\\uDE00\"}";
        Assert.True(new KeyBindingValidator().ValidateKeyBinding(
            SignHolder(holder, holderHeader),
            holder.ExportSubjectPublicKeyInfo(), "hash", "audience", "nonce"));
    }

    private static string SignIssuer(string header)
    {
        const string payload = /*lang=json,strict*/ """{"exp":4102444800,"_sd_alg":"sha-256","_sd":[]}""";
        var input = Base64UrlEncoder.Encode(header) + "." + Base64UrlEncoder.Encode(payload);
        return input + "." + Base64UrlEncoder.Encode(
            HMACSHA256.HashData(_issuerKey, System.Text.Encoding.ASCII.GetBytes(input)));
    }

    private static string SignHolder(ECDsa holder, string header)
    {
        var payload = "{\"sd_hash\":\"hash\",\"aud\":\"audience\",\"nonce\":\"nonce\",\"iat\":" +
            DateTimeOffset.UtcNow.ToUnixTimeSeconds() + "}";
        var input = Base64UrlEncoder.Encode(header) + "." + Base64UrlEncoder.Encode(payload);
        return input + "." + Base64UrlEncoder.Encode(
            holder.SignData(System.Text.Encoding.ASCII.GetBytes(input), HashAlgorithmName.SHA256));
    }
}
