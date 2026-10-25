using HeroSdJwt.Models;
using HeroSdJwt.Presentation;
using HeroSdJwt.Primitives;

namespace HeroSdJwt.Tests.Unit.Presentation;

/// <summary>
/// Regression tests for disclosure selection by qualified claim paths.
/// </summary>
public class SdJwtPresenterClaimSelectionTests
{
    [Fact]
    public void Should_IncludeImmediateParent_When_DisclosingNestedChild()
    {
        var credential = CreateCredential(
            ["parent", "child"],
            new Dictionary<string, int>
            {
                ["profile"] = 0,
                ["profile.email"] = 1
            });

        var presentation = new SdJwtPresenter().CreatePresentation(credential, ["profile.email"]);

        Assert.Equal(new[] { "parent", "child" }, presentation.SelectedDisclosures);
    }

    [Fact]
    public void Should_IncludeEveryAncestor_When_DisclosingDeepNestedChild()
    {
        var credential = CreateCredential(
            ["parent", "middle", "child"],
            new Dictionary<string, int>
            {
                ["profile"] = 0,
                ["profile.contact"] = 1,
                ["profile.contact.email"] = 2
            });

        var presentation = new SdJwtPresenter().CreatePresentation(credential, ["profile.contact.email"]);

        Assert.Equal(new[] { "parent", "middle", "child" }, presentation.SelectedDisclosures);
    }

    [Fact]
    public void Should_IncludeArrayAndObjectAncestors_When_DisclosingNestedArrayProperty()
    {
        var credential = CreateCredential(
            ["array", "element", "contact", "email"],
            new Dictionary<string, int>
            {
                ["records"] = 0,
                ["records[1]"] = 1,
                ["records[1].contact"] = 2,
                ["records[1].contact.email"] = 3
            });

        var presentation = new SdJwtPresenter().CreatePresentation(credential, ["records[1].contact.email"]);

        Assert.Equal(new[] { "array", "element", "contact", "email" }, presentation.SelectedDisclosures);
    }

    [Fact]
    public void Should_IncludeEachNestedArrayAncestor_When_DisclosingArrayChild()
    {
        var credential = CreateCredential(
            ["array", "outer", "inner", "name"],
            new Dictionary<string, int>
            {
                ["groups"] = 0,
                ["groups[2]"] = 1,
                ["groups[2][1]"] = 2,
                ["groups[2][1].name"] = 3
            });

        var presentation = new SdJwtPresenter().CreatePresentation(credential, ["groups[2][1].name"]);

        Assert.Equal(new[] { "array", "outer", "inner", "name" }, presentation.SelectedDisclosures);
    }

    [Fact]
    public void Should_RejectAmbiguousShortName_InsteadOfDisclosingArbitraryClaim()
    {
        var credential = CreateCredential(
            ["billing", "shipping"],
            new Dictionary<string, int>
            {
                ["billing.email"] = 0,
                ["shipping.email"] = 1
            });

        var exception = Assert.Throws<ArgumentException>(() =>
            new SdJwtPresenter().CreatePresentation(credential, ["email"]));

        Assert.Contains("ambiguous", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("selectedClaimNames", exception.ParamName);
    }

    [Fact]
    public void Should_UseExactlyQualifiedName_When_ShortNameIsAmbiguous()
    {
        var credential = CreateCredential(
            ["billing", "shipping"],
            new Dictionary<string, int>
            {
                ["billing.email"] = 0,
                ["shipping.email"] = 1
            });

        var presentation = new SdJwtPresenter().CreatePresentation(credential, ["shipping.email"]);

        Assert.Equal(new[] { "shipping" }, presentation.SelectedDisclosures);
    }

    [Fact]
    public void Should_PreferExactTopLevelName_OverOtherQualifiedNames()
    {
        var credential = CreateCredential(
            ["root", "nested"],
            new Dictionary<string, int>
            {
                ["email"] = 0,
                ["shipping.email"] = 1
            });

        var presentation = new SdJwtPresenter().CreatePresentation(credential, ["email"]);

        Assert.Equal(new[] { "root" }, presentation.SelectedDisclosures);
    }

    [Fact]
    public void Should_KeepUniqueShortNameConvenience_When_OnlyOnePathMatches()
    {
        var credential = CreateCredential(
            ["name", "email"],
            new Dictionary<string, int>
            {
                ["billing.name"] = 0,
                ["shipping.email"] = 1
            });

        var presentation = new SdJwtPresenter().CreatePresentation(credential, ["email"]);

        Assert.Equal(new[] { "email" }, presentation.SelectedDisclosures);
    }

    private static SdJwt CreateCredential(string[] disclosures, Dictionary<string, int> mapping)
    {
        return new SdJwt(
            "header.payload.signature",
            disclosures,
            HashAlgorithm.Sha256,
            claimPathMapping: mapping);
    }
}
