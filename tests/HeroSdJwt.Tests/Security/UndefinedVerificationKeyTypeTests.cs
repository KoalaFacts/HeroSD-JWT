using HeroSdJwt.Primitives;
using HeroSdJwt.Verification;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Unknown numeric enum values must not turn a configured key-type policy
/// into the permissive Either policy during verification.
/// </summary>
public class UndefinedVerificationKeyTypeTests
{
    [Theory]
    [InlineData(-1)]
    [InlineData(3)]
    [InlineData(int.MaxValue)]
    public void Should_RejectUndefinedKeyType_When_ValidatingOptions(int undefinedValue)
    {
        var options = new SdJwtVerificationOptions
        {
            ExpectedKeyType = (VerificationKeyType)undefinedValue
        };

        var error = Assert.Throws<ArgumentOutOfRangeException>(options.Validate);
        Assert.Equal(nameof(SdJwtVerificationOptions.ExpectedKeyType), error.ParamName);
    }

    [Fact]
    public void Should_RejectUndefinedKeyType_When_ConstructingVerifier()
    {
        // A typo or numeric configuration binding must fail before the
        // verifier could accept HMAC signatures under an unintended Either policy.
        var options = new SdJwtVerificationOptions
        {
            ExpectedKeyType = (VerificationKeyType)42
        };

        var error = Assert.Throws<ArgumentOutOfRangeException>(() => TestHelpers.CreateVerifier(options));
        Assert.Equal(nameof(SdJwtVerificationOptions.ExpectedKeyType), error.ParamName);
    }
}
