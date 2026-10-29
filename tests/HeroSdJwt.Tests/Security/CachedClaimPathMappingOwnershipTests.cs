using HeroSdJwt.Models;
using HeroSdJwt.Presentation;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;
using RandomNumberGenerator = System.Security.Cryptography.RandomNumberGenerator;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// A cached holder claim-path mapping must not change after the credential is created.
/// Otherwise selecting a public claim could silently reveal a different disclosure.
/// </summary>
public class CachedClaimPathMappingOwnershipTests
{
    [Fact]
    public void Should_NotRevealAnotherClaim_When_SourceMappingChangesAfterConstruction()
    {
        var issued = IssueCredential();
        var sourceMapping = new Dictionary<string, int>(issued.ClaimPathMapping!);
        var credential = new SdJwt(
            issued.Jwt,
            issued.Disclosures,
            issued.HashAlgorithm,
            claimPathMapping: sourceMapping);
        var expectedEmailDisclosure = issued.Disclosures[sourceMapping["email"]];

        // The caller still owns this dictionary, but not the credential's mapping.
        sourceMapping["email"] = sourceMapping["tax_id"];

        var presentation = new SdJwtPresenter().CreatePresentation(credential, ["email"]);

        Assert.Equal(expectedEmailDisclosure, Assert.Single(presentation.SelectedDisclosures));
    }

    [Fact]
    public void Should_RejectMutation_When_ExposingCachedMappingToConsumers()
    {
        var issued = IssueCredential();
        var exposedMapping = Assert.IsAssignableFrom<IDictionary<string, int>>(issued.ClaimPathMapping);
        var taxIdIndex = issued.ClaimPathMapping!["tax_id"];

        // IReadOnlyDictionary alone is insufficient when the object is a Dictionary.
        _ = Assert.Throws<NotSupportedException>(() => exposedMapping["email"] = taxIdIndex);
    }

    private static SdJwt IssueCredential()
    {
        var claims = new Dictionary<string, object>
        {
            ["sub"] = "user-123",
            ["email"] = "user@example.com",
            ["tax_id"] = "123-45-6789"
        };

        return TestHelpers.CreateIssuer().CreateSdJwt(
            claims,
            ["email", "tax_id"],
            RandomNumberGenerator.GetBytes(32),
            HashAlgorithm.Sha256);
    }
}
