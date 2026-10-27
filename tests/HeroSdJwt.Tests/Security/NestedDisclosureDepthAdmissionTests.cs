using HeroSdJwt.Encoding;
using HeroSdJwt.Issuance;
using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;
using System.Security.Cryptography;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// A presented Disclosure cannot bypass the verifier's nested JSON admission
/// limit merely because its nested digest collection raised an exception.
/// The issuer's signature and the outer Disclosure digest are both valid.
/// </summary>
public class NestedDisclosureDepthAdmissionTests
{
    private static readonly byte[] _signingKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Theory]
    [InlineData(9, false, true)]
    [InlineData(10, false, true)]
    [InlineData(11, false, false)]
    [InlineData(12, false, false)]
    [InlineData(11, true, false)]
    [InlineData(12, true, false)]
    public async Task Should_FailClosed_WhenSignedDisclosureExceedsNestedDigestDepth(
        int nestingDepth, bool useArrays, bool shouldAccept)
    {
        var claimValue = "42";
        for (var i = 0; i < nestingDepth; i++)
        {
            claimValue = useArrays ? $"[{claimValue}]" : $"{{\"child\":{claimValue}}}";
        }

        var disclosure = Base64UrlEncoder.Encode(
            $"[\"fixed-salt\",\"profile\",{claimValue}]");
        var digest = new DigestCalculator().ComputeDigest(disclosure, HashAlgorithm.Sha256);
        var payload = $"{{\"exp\":4102444800,\"_sd\":[\"{digest}\"]}}";
        var header = Base64UrlEncoder.Encode(/*lang=json,strict*/ """{"alg":"HS256","kid":"depth-test-key"}""");
        var signingInput = header + "." + Base64UrlEncoder.Encode(payload);
        var signature = HMACSHA256.HashData(_signingKey, System.Text.Encoding.UTF8.GetBytes(signingInput));
        var presentation = signingInput + "." + Base64UrlEncoder.Encode(signature) + "~" + disclosure + "~";
        var verifier = SdJwtVerifierBuilder.Create()
            .WithExpectedKeyType(VerificationKeyType.Symmetric)
            .Build();

        var direct = verifier.TryVerifyPresentation(presentation, _signingKey);
        var resolved = verifier.TryVerifyPresentation(presentation,
            kid => kid == "depth-test-key" ? _signingKey : null);
        var asyncDirect = await verifier.TryVerifyPresentationAsync(
            presentation, _signingKey, cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(shouldAccept, direct.IsValid);
        Assert.Equal(shouldAccept, resolved.IsValid);
        Assert.Equal(shouldAccept, asyncDirect.IsValid);

        if (shouldAccept)
        {
            Assert.NotEqual(System.Text.Json.JsonValueKind.Undefined, direct.DisclosedClaims["profile"].ValueKind);
        }
        else
        {
            Assert.Contains(ErrorCode.InvalidInput, direct.Errors);
            Assert.Contains(ErrorCode.InvalidInput, resolved.Errors);
            Assert.Contains(ErrorCode.InvalidInput, asyncDirect.Errors);
        }
    }
}
