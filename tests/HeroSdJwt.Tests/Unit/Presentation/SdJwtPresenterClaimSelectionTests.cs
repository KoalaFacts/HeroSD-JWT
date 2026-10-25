using HeroSdJwt.Encoding;
using HeroSdJwt.Issuance;
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
        var email = ObjectDisclosure("email", "\"public@example.com\"");
        var profile = ObjectDisclosure("profile", NestedObject(Digest(email)));
        var credential = CreateCredential(
            [profile, email],
            new Dictionary<string, int>
            {
                ["profile"] = 0,
                ["profile.email"] = 1
            });

        var presentation = new SdJwtPresenter().CreatePresentation(credential, ["profile.email"]);

        Assert.Equal(new[] { profile, email }, presentation.SelectedDisclosures);
    }

    [Fact]
    public void Should_IncludeEveryAncestor_When_DisclosingDeepNestedChild()
    {
        var email = ObjectDisclosure("email", "\"public@example.com\"");
        var contact = ObjectDisclosure("contact", NestedObject(Digest(email)));
        var profile = ObjectDisclosure("profile", NestedObject(Digest(contact)));
        var credential = CreateCredential(
            [profile, contact, email],
            new Dictionary<string, int>
            {
                ["profile"] = 0,
                ["profile.contact"] = 1,
                ["profile.contact.email"] = 2
            });

        var presentation = new SdJwtPresenter().CreatePresentation(credential, ["profile.contact.email"]);

        Assert.Equal(new[] { profile, contact, email }, presentation.SelectedDisclosures);
    }

    [Fact]
    public void Should_IncludeArrayAndObjectAncestors_When_DisclosingNestedArrayProperty()
    {
        var email = ObjectDisclosure("email", "\"public@example.com\"");
        var contact = ObjectDisclosure("contact", NestedObject(Digest(email)));
        var element = ArrayDisclosure(NestedObject(Digest(contact)));
        var records = ObjectDisclosure("records", $"[null,{ArrayPlaceholder(Digest(element))}]");
        var credential = CreateCredential(
            [records, element, contact, email],
            new Dictionary<string, int>
            {
                ["records"] = 0,
                ["records[1]"] = 1,
                ["records[1].contact"] = 2,
                ["records[1].contact.email"] = 3
            });

        var presentation = new SdJwtPresenter().CreatePresentation(credential, ["records[1].contact.email"]);

        Assert.Equal(new[] { records, element, contact, email }, presentation.SelectedDisclosures);
    }

    [Fact]
    public void Should_IncludeEachNestedArrayAncestor_When_DisclosingArrayChild()
    {
        var name = ObjectDisclosure("name", "\"shown\"");
        var inner = ArrayDisclosure(NestedObject(Digest(name)));
        var outer = ArrayDisclosure($"[null,{ArrayPlaceholder(Digest(inner))}]");
        var groups = ObjectDisclosure("groups", $"[null,null,{ArrayPlaceholder(Digest(outer))}]");
        var credential = CreateCredential(
            [groups, outer, inner, name],
            new Dictionary<string, int>
            {
                ["groups"] = 0,
                ["groups[2]"] = 1,
                ["groups[2][1]"] = 2,
                ["groups[2][1].name"] = 3
            });

        var presentation = new SdJwtPresenter().CreatePresentation(credential, ["groups[2][1].name"]);

        Assert.Equal(new[] { groups, outer, inner, name }, presentation.SelectedDisclosures);
    }

    [Theory]
    [InlineData("profile", "profile.email")]
    [InlineData("records", "records[1]")]
    public void Should_NotDiscloseUnrelatedLiteralPrefix_When_NameContainsPathCharacters(string prefix, string literalName)
    {
        var unrelated = ObjectDisclosure(prefix, "\"private\"");
        var selected = ObjectDisclosure(literalName, "\"public\"");
        var credential = CreateCredential(
            [unrelated, selected],
            new Dictionary<string, int>
            {
                [prefix] = 0,
                [literalName] = 1
            });

        var presentation = new SdJwtPresenter().CreatePresentation(credential, [literalName]);

        Assert.Equal(new[] { selected }, presentation.SelectedDisclosures);
    }

    [Fact]
    public void Should_NotDiscloseUnboundGrandparent_When_OnlyMiddleAndChildAreRelated()
    {
        var email = ObjectDisclosure("email", "\"shown\"");
        var contact = ObjectDisclosure("contact", NestedObject(Digest(email)));
        var unrelated = ObjectDisclosure("profile", "\"secret\"");
        var credential = CreateCredential(
            [unrelated, contact, email],
            new Dictionary<string, int>
            {
                ["profile"] = 0,
                ["profile.contact"] = 1,
                ["profile.contact.email"] = 2
            });

        var presentation = new SdJwtPresenter().CreatePresentation(credential, ["profile.contact.email"]);

        Assert.Equal(new[] { contact, email }, presentation.SelectedDisclosures);
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

    private static string ObjectDisclosure(string name, string rawJsonValue)
    {
        return Base64UrlEncoder.Encode($"[\"salt\",\"{name}\",{rawJsonValue}]");
    }

    private static string ArrayDisclosure(string rawJsonValue)
    {
        return Base64UrlEncoder.Encode($"[\"salt\",{rawJsonValue}]");
    }

    private static string NestedObject(string digest)
    {
        return $"{{\"_sd\":[\"{digest}\"]}}";
    }

    private static string ArrayPlaceholder(string digest)
    {
        return $"{{\"...\":\"{digest}\"}}";
    }

    private static string Digest(string disclosure)
    {
        return new DigestCalculator().ComputeDigest(disclosure, HashAlgorithm.Sha256);
    }
}
