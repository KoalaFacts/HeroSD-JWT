using HeroSdJwt.Cryptography;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// A JWT issued within the public 64-KiB wire limit must be consumable
/// through an SD-JWT presentation, regardless of the signing-key entry point.
/// </summary>
public class IntegratedJwtSizeAdmissionTests
{
    private static readonly byte[] _signingKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Theory]
    [InlineData(20_000, false)]
    [InlineData(27_000, true)]
    public async Task Should_VerifySignedJwtWithinPresentationLimit_RegardlessOfComponentSize(
        int noteLength, bool exceedsHalfLimit)
    {
        const string keyId = "size-admission-key";
        var payload = new Dictionary<string, object>
        {
            ["exp"] = 4102444800L,
            ["note"] = new string('x', noteLength)
        };
        var jwt = new JwtSigner().CreateJwt(payload, _signingKey, SignatureAlgorithm.HS256, keyId);
        var presentation = jwt + "~";

        Assert.Equal(exceedsHalfLimit, jwt.Length > Constants.MAX_JWT_SIZE_BYTES / 2);
        Assert.True(presentation.Length <= Constants.MAX_JWT_SIZE_BYTES);
        Assert.True(new SignatureValidator().VerifyJwtSignature(jwt, _signingKey));

        var verifier = SdJwtVerifierBuilder.Create()
            .WithExpectedKeyType(VerificationKeyType.Symmetric)
            .Build();

        var direct = verifier.TryVerifyPresentation(presentation, _signingKey);
        Assert.True(direct.IsValid, direct.ErrorDetails);

        var resolved = verifier.TryVerifyPresentation(
            presentation, keyIdToResolve => keyIdToResolve == keyId ? _signingKey : null);
        Assert.True(resolved.IsValid, resolved.ErrorDetails);

        var asyncDirect = await verifier.TryVerifyPresentationAsync(
            presentation, _signingKey,
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.True(asyncDirect.IsValid, asyncDirect.ErrorDetails);

        var asyncResolved = await verifier.TryVerifyPresentationAsync(
            presentation, keyIdToResolve => keyIdToResolve == keyId ? _signingKey : null,
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.True(asyncResolved.IsValid, asyncResolved.ErrorDetails);
    }
}
