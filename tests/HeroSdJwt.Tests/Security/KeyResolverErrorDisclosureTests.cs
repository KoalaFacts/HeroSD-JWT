using HeroSdJwt.Exceptions;
using HeroSdJwt.Extensions;
using HeroSdJwt.Issuance;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// A key resolver may use a database or KMS whose exception text contains secrets.
/// Verification results and exceptions must not expose that backend diagnostic text.
/// </summary>
public class KeyResolverErrorDisclosureTests
{
    private const string BACKEND_SECRET = "password=private-key-store-secret";
    private static readonly byte[] _signingKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Should_NotExposeBackendExceptionDetails_WhenKeyResolverFails(bool domainException)
    {
        var presentation = SdJwtIssuerBuilder.Create()
            .WithKeyId("issuer-key")
            .WithClaim("sub", "subject")
            .WithClaim("exp", DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds())
            .SignWithHmac(_signingKey)
            .Build()
            .ToPresentation();

        var verifier = TestHelpers.CreateVerifier(new SdJwtVerificationOptions
        {
            ExpectedKeyType = VerificationKeyType.Symmetric
        });

        byte[]? resolver(string _)
        {
            if (domainException)
            {
                throw new SdJwtException(BACKEND_SECRET, ErrorCode.InvalidInput);
            }

            throw new IOException(BACKEND_SECRET);
        }

        var syncResult = verifier.TryVerifyPresentation(presentation, resolver);
        Assert.False(syncResult.IsValid);
        Assert.Contains(ErrorCode.KeyResolverFailed, syncResult.Errors);
        Assert.DoesNotContain(BACKEND_SECRET, syncResult.ErrorDetails ?? string.Empty, StringComparison.Ordinal);

        var syncException = Assert.Throws<SdJwtException>(() =>
            verifier.VerifyPresentation(presentation, resolver));
        Assert.Equal(ErrorCode.KeyResolverFailed, syncException.ErrorCode);
        Assert.DoesNotContain(BACKEND_SECRET, syncException.ToString(), StringComparison.Ordinal);

        var asyncResult = await verifier.TryVerifyPresentationAsync(
            presentation, resolver, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(asyncResult.IsValid);
        Assert.Contains(ErrorCode.KeyResolverFailed, asyncResult.Errors);
        Assert.DoesNotContain(BACKEND_SECRET, asyncResult.ErrorDetails ?? string.Empty, StringComparison.Ordinal);

        var asyncException = await Assert.ThrowsAsync<SdJwtException>(() =>
            verifier.VerifyPresentationAsync(
                presentation, resolver, cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(ErrorCode.KeyResolverFailed, asyncException.ErrorCode);
        Assert.DoesNotContain(BACKEND_SECRET, asyncException.ToString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Should_NotExposeBackendExceptionDetails_WhenStandaloneSignatureResolverFails(bool domainException)
    {
        var jwt = SdJwtIssuerBuilder.Create()
            .WithKeyId("issuer-key")
            .WithClaim("sub", "subject")
            .SignWithHmac(_signingKey)
            .Build()
            .Jwt;

        byte[]? resolver(string _)
        {
            if (domainException)
            {
                throw new SdJwtException(BACKEND_SECRET, ErrorCode.InvalidInput);
            }

            throw new IOException(BACKEND_SECRET);
        }

        var exception = Assert.Throws<SdJwtException>(() =>
            new SignatureValidator().VerifyJwtSignature(jwt, resolver));
        Assert.Equal(ErrorCode.KeyResolverFailed, exception.ErrorCode);
        Assert.DoesNotContain(BACKEND_SECRET, exception.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Should_PreserveCancellationAndMissingKey_WhenStandaloneSignatureResolverDoesNotResolve()
    {
        var jwt = SdJwtIssuerBuilder.Create()
            .WithKeyId("issuer-key")
            .WithClaim("sub", "subject")
            .SignWithHmac(_signingKey)
            .Build()
            .Jwt;

        Assert.ThrowsAny<OperationCanceledException>(() =>
            new SignatureValidator().VerifyJwtSignature(
                jwt, _ => throw new OperationCanceledException("Key store canceled")));

        var exception = Assert.Throws<SdJwtException>(() =>
            new SignatureValidator().VerifyJwtSignature(jwt, _ => null));
        Assert.Equal(ErrorCode.KeyIdNotFound, exception.ErrorCode);
    }
}
