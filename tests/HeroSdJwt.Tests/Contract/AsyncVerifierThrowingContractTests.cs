using HeroSdJwt.Exceptions;
using HeroSdJwt.Extensions;
using HeroSdJwt.Issuance;
using HeroSdJwt.Models;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;

namespace HeroSdJwt.Tests.Contract;

/// <summary>
/// The legacy asynchronous VerifyPresentation methods promise to throw on
/// verification failure, just like the synchronous methods. They must not
/// silently return an invalid result to consumers who use this contract.
/// </summary>
public class AsyncVerifierThrowingContractTests
{
    private static readonly byte[] _signingKey = Enumerable.Repeat((byte)0x41, 32).ToArray();
    private static readonly byte[] _wrongKey = Enumerable.Repeat((byte)0x42, 32).ToArray();

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Should_ThrowForInvalidSignature_When_CallingVerifyPresentationAsync(bool useResolver)
    {
        var presentation = SdJwtIssuerBuilder.Create()
            .WithKeyId("async-throwing-contract")
            .WithClaim("sub", "example")
            .SignWithHmac(_signingKey)
            .Build()
            .ToPresentation();
        ISdJwtVerifierAsync verifier = SdJwtVerifierBuilder.Create()
            .WithExpectedKeyType(VerificationKeyType.Symmetric)
            .Build();

        Task<VerificationResult> Verify() => useResolver
            ? verifier.VerifyPresentationAsync(
                presentation,
                (KeyResolver)(_ => _wrongKey),
                cancellationToken: TestContext.Current.CancellationToken)
            : verifier.VerifyPresentationAsync(
                presentation,
                _wrongKey,
                cancellationToken: TestContext.Current.CancellationToken);

        var error = await Assert.ThrowsAsync<SdJwtException>(Verify);
        Assert.Equal(ErrorCode.InvalidSignature, error.ErrorCode);
    }
}
