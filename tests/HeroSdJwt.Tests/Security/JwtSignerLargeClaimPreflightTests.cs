using HeroSdJwt.Cryptography;
using HeroSdJwt.Primitives;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// An impossibly large individual claim name or value must be rejected before
/// the JSON writer allocates a large UTF-8 buffer for a JWT the verifier cannot accept.
/// </summary>
public sealed class JwtSignerLargeClaimPreflightTests
{
    [Theory]
    [InlineData("string-value")]
    [InlineData("top-level-name")]
    [InlineData("nested-object-name")]
    [InlineData("nested-string-name")]
    [InlineData("nested-string-value")]
    [InlineData("dictionary-name")]
    public void Should_RejectImpossibleClaimComponentBeforeLargeJsonAllocation(string shape)
    {
        // Construct the hostile input outside the measured region. The current
        // serializer consumes much more than this budget when writing a single
        // oversized property name or value before checking its wire-size limit.
        var oversized = new string('x', Constants.MAX_JWT_SIZE_BYTES * 8);
        var claims = shape switch
        {
            "string-value" => new Dictionary<string, object> { ["payload"] = oversized },
            "top-level-name" => new Dictionary<string, object> { [oversized] = "short" },
            "nested-object-name" => new Dictionary<string, object>
            {
                ["profile"] = new Dictionary<string, object> { [oversized] = "short" }
            },
            "nested-string-name" => new Dictionary<string, object>
            {
                ["profile"] = new Dictionary<string, string> { [oversized] = "short" }
            },
            "nested-string-value" => new Dictionary<string, object>
            {
                ["profile"] = new Dictionary<string, string> { ["payload"] = oversized }
            },
            "dictionary-name" => new Dictionary<string, object>
            {
                ["profile"] = new System.Collections.Hashtable { [oversized] = "short" }
            },
            _ => throw new ArgumentOutOfRangeException(nameof(shape))
        };

        var signer = new JwtSigner();
        var signingKey = new byte[32];

        // Warm the normal successful signing path outside the allocation count.
        _ = signer.CreateJwt(
            new Dictionary<string, object> { ["sub"] = "warmup" },
            signingKey,
            SignatureAlgorithm.HS256);

        var before = GC.GetAllocatedBytesForCurrentThread();
        var exception = Assert.Throws<ArgumentException>(() =>
            signer.CreateJwt(claims, signingKey, SignatureAlgorithm.HS256));
        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        Assert.Contains("maximum allowed size", exception.Message);
        Assert.InRange(allocated, 0L, 128_000L);
    }
}
