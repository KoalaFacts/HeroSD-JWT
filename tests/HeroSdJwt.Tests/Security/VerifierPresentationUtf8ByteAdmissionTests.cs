using HeroSdJwt.Issuance;
using HeroSdJwt.Models;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Text;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// The 64-KiB presentation admission limit is a UTF-8 wire-byte limit,
/// not a UTF-16 character limit. Reject oversized untrusted input before
/// invoking key-resolution services or signature verification.
/// </summary>
public class VerifierPresentationUtf8ByteAdmissionTests
{
    private static readonly byte[] _signingKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Should_RejectUtf8OversizedPresentation_BeforeResolvingKey(bool asynchronous)
    {
        var presentation = CreateOversizedPresentation();
        var verifier = CreateVerifier();
        var resolverCalls = 0;

        byte[]? ResolveKey(string _)
        {
            resolverCalls++;
            return _signingKey;
        }

        VerificationResult result = asynchronous
            ? await verifier.TryVerifyPresentationAsync(
                presentation, ResolveKey, cancellationToken: TestContext.Current.CancellationToken)
            : verifier.TryVerifyPresentation(presentation, ResolveKey);

        Assert.False(result.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, result.Errors);
        Assert.Equal(0, resolverCalls);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Should_RejectUtf8OversizedPresentation_AtDirectKeyEntryPoint(bool asynchronous)
    {
        var presentation = CreateOversizedPresentation();
        var verifier = CreateVerifier();

        VerificationResult result = asynchronous
            ? await verifier.TryVerifyPresentationAsync(
                presentation, _signingKey, cancellationToken: TestContext.Current.CancellationToken)
            : verifier.TryVerifyPresentation(presentation, _signingKey);

        Assert.False(result.IsValid);
        Assert.Contains(ErrorCode.InvalidInput, result.Errors);
        Assert.Contains(
            "Presentation exceeds maximum allowed size",
            result.ErrorDetails ?? string.Empty,
            StringComparison.Ordinal);
    }

    private static SdJwtVerifier CreateVerifier() =>
        TestHelpers.CreateVerifier(new SdJwtVerificationOptions
        {
            ExpectedKeyType = VerificationKeyType.Symmetric
        });

    private static string CreateOversizedPresentation()
    {
        var jwt = SdJwtIssuerBuilder.Create()
            .WithKeyId("utf8-size-check")
            .WithClaim("sub", "utf8-size-check")
            .WithClaim("exp", DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds())
            .SignWithHmac(_signingKey)
            .Build()
            .Jwt;

        // An attacker-controlled component can be short in UTF-16 but
        // several times larger in the actual UTF-8 request body.
        var presentation = jwt + "~" + new string('漢', 25_000) + "~";
        Assert.True(presentation.Length <= Constants.MAX_JWT_SIZE_BYTES);
        Assert.True(Encoding.UTF8.GetByteCount(presentation) > Constants.MAX_JWT_SIZE_BYTES);

        return presentation;
    }
}
