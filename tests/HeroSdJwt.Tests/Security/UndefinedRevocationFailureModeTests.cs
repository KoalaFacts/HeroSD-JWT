using HeroSdJwt.Verification;
using HeroSdJwt.Verification.Revocation;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Unrecognized revocation failure modes must be rejected as configuration
/// errors rather than silently selecting an undocumented outage policy.
/// </summary>
public class UndefinedRevocationFailureModeTests
{
    [Theory]
    [InlineData(-1)]
    [InlineData(2)]
    [InlineData(int.MaxValue)]
    public void Should_RejectUndefinedRevocationFailureMode_When_ValidatingOptions(int rawValue)
    {
        var options = new SdJwtVerificationOptions
        {
            Revocation = new RevocationOptions
            {
                FailureMode = (RevocationFailureMode)rawValue
            }
        };

        var exception = Assert.Throws<ArgumentOutOfRangeException>(options.Validate);
        Assert.Equal(nameof(RevocationOptions.FailureMode), exception.ParamName);
    }

    [Fact]
    public void Should_RejectUndefinedRevocationFailureMode_When_BuildingVerifier()
    {
        using var store = new InMemoryRevocationStore();

        var exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
            SdJwtVerifierBuilder.Create()
                .WithRevocation(store, (RevocationFailureMode)42)
                .Build());

        Assert.Equal(nameof(RevocationOptions.FailureMode), exception.ParamName);
    }

    [Theory]
    [InlineData(RevocationFailureMode.FailClosed)]
    [InlineData(RevocationFailureMode.FailOpen)]
    public void Should_AcceptDocumentedRevocationFailureModes_When_ValidatingOptions(RevocationFailureMode failureMode)
    {
        var options = new SdJwtVerificationOptions
        {
            Revocation = new RevocationOptions
            {
                FailureMode = failureMode
            }
        };

        options.Validate();
    }
}
