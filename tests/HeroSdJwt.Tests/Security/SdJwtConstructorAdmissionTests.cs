using HeroSdJwt.Models;
using HeroSdJwt.Primitives;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Credential issuance can exceed the 100-disclosure presentation limit,
/// but a hostile lazy source must not exhaust memory without any ceiling.
/// </summary>
public class SdJwtConstructorAdmissionTests
{
    [Fact]
    public void Should_AllowMoreThanPresentationLimit_DuringCredentialConstruction()
    {
        var sdJwt = new SdJwt(
            "header.payload.signature",
            Enumerable.Repeat("W10", Constants.MAX_DISCLOSURES + 1),
            HashAlgorithm.Sha256);

        Assert.Equal(Constants.MAX_DISCLOSURES + 1, sdJwt.Disclosures.Count);
    }

    [Fact]
    public void Should_RejectUnboundedCredentialDisclosureCount()
    {
        var error = Assert.Throws<ArgumentException>(() =>
            new SdJwt(
                "header.payload.signature",
                Enumerable.Repeat("W10", SdJwt.MAX_CREDENTIAL_DISCLOSURES + 1),
                HashAlgorithm.Sha256));

        Assert.Equal("disclosures", error.ParamName);
    }

    [Fact]
    public void Should_StopReadingLazySource_AfterFirstExcessCredentialDisclosure()
    {
        static IEnumerable<string> AdversarialStream()
        {
            for (var i = 0; i < SdJwt.MAX_CREDENTIAL_DISCLOSURES + 1; i++)
            {
                yield return "W10";
            }

            throw new InvalidOperationException("Source was consumed beyond the credential limit.");
        }

        var error = Assert.Throws<ArgumentException>(() =>
            new SdJwt("header.payload.signature", AdversarialStream(), HashAlgorithm.Sha256));
        Assert.Equal("disclosures", error.ParamName);
    }

    [Fact]
    public void Should_AcceptExactlyConservativeCredentialDisclosureLimit()
    {
        var sdJwt = new SdJwt(
            "header.payload.signature",
            Enumerable.Repeat("W10", SdJwt.MAX_CREDENTIAL_DISCLOSURES),
            HashAlgorithm.Sha256);

        Assert.Equal(SdJwt.MAX_CREDENTIAL_DISCLOSURES, sdJwt.Disclosures.Count);
    }

    [Fact]
    public void Should_AllowLargeImportedCredential_ButRejectItsWireSerialization()
    {
        // Signed large JWTs must remain available for holder-side mapping.
        // The 64-KiB limit applies only when serializing a presentation.
        var jwt = new string('a', Constants.MAX_JWT_SIZE_BYTES + 1);
        var credential = new SdJwt(jwt, [], HashAlgorithm.Sha256);

        Assert.Equal(jwt, credential.Jwt);
        _ = Assert.Throws<ArgumentException>(credential.ToCombinedFormat);
    }

    [Fact]
    public void Should_AllowLargeAttachedKeyBindingInCredential_ButRejectWireSerialization()
    {
        var keyBinding = new string('a', Constants.MAX_JWT_SIZE_BYTES);
        var credential = new SdJwt(
            "header.payload.signature", [], HashAlgorithm.Sha256, keyBinding);

        Assert.Equal(keyBinding, credential.KeyBindingJwt);
        _ = Assert.Throws<ArgumentException>(credential.ToCombinedFormat);
    }
}
