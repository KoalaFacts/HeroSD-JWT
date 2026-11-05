using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Compact JWS signature bytes must have one canonical, unpadded base64url
/// representation regardless of whether the caller supplies a direct key or a resolver.
/// </summary>
public sealed class DirectKeySignatureCanonicalizationTests
{
    private static readonly byte[] _key = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];
    private const string BASE64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    [Fact]
    public void Should_RejectNonzeroUnusedSignatureBits_WithDirectSignatureValidator()
    {
        var jwt = SignJwt();
        var altered = WithNoncanonicalSignature(jwt);

        Assert.True(new SignatureValidator().VerifyJwtSignature(jwt, _key));
        Assert.False(SignatureValidator.HasCanonicalBase64UrlEncoding(altered.AsSpan(altered.LastIndexOf('.') + 1)));

        var exception = Assert.Throws<SdJwtException>(() =>
            new SignatureValidator().VerifyJwtSignature(altered, _key));
        Assert.Equal(ErrorCode.InvalidInput, exception.ErrorCode);
    }

    [Fact]
    public async Task Should_RejectNonzeroUnusedSignatureBits_WithDirectPresentationVerifier()
    {
        var jwt = SignJwt();
        var altered = WithNoncanonicalSignature(jwt);
        var verifier = SdJwtVerifierBuilder.Create()
            .WithExpectedKeyType(VerificationKeyType.Symmetric)
            .Build();

        var valid = verifier.TryVerifyPresentation(jwt + "~", _key);
        Assert.True(valid.IsValid, valid.ErrorDetails);

        var sync = verifier.TryVerifyPresentation(altered + "~", _key);
        Assert.False(sync.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, sync.Errors);

        var asyncResult = await verifier.TryVerifyPresentationAsync(
            altered + "~", _key, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(asyncResult.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, asyncResult.Errors);
    }

    private static string SignJwt()
    {
        const string header = /*lang=json,strict*/ """{"alg":"HS256"}""";
        const string payload = /*lang=json,strict*/ """{"exp":4102444800}""";
        var signingInput = Base64UrlEncoder.Encode(header) + "." + Base64UrlEncoder.Encode(payload);
        var signature = HMACSHA256.HashData(_key, System.Text.Encoding.UTF8.GetBytes(signingInput));
        return signingInput + "." + Base64UrlEncoder.Encode(signature);
    }

    private static string WithNoncanonicalSignature(string jwt)
    {
        var last = jwt[^1];
        var index = BASE64URL_ALPHABET.IndexOf(last);
        // HS256 emits 32 bytes, so the last sextet has two unused zero bits.
        Assert.True(index >= 0 && index % 4 == 0);
        return jwt[..^1] + BASE64URL_ALPHABET[index + 1];
    }
}
