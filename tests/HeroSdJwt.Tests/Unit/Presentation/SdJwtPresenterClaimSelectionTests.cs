using HeroSdJwt.Cryptography;
using HeroSdJwt.Encoding;
using HeroSdJwt.Issuance;
using HeroSdJwt.Models;
using HeroSdJwt.Presentation;
using HeroSdJwt.Primitives;
using System.Security.Cryptography;

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

        string[] expected = [profile, email];
        Assert.Equal(expected, presentation.SelectedDisclosures);
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

        string[] expected = [profile, contact, email];
        Assert.Equal(expected, presentation.SelectedDisclosures);
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

        string[] expected = [records, element, contact, email];
        Assert.Equal(expected, presentation.SelectedDisclosures);
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

        string[] expected = [groups, outer, inner, name];
        Assert.Equal(expected, presentation.SelectedDisclosures);
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

        string[] expected = [selected];
        Assert.Equal(expected, presentation.SelectedDisclosures);
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

        string[] expected = [contact, email];
        Assert.Equal(expected, presentation.SelectedDisclosures);
    }

    [Theory]
    [InlineData("profile", "profile.email")]
    [InlineData("records", "records[1]")]
    public void Should_NotLeakLiteralPrefix_When_ImportingSignedCredentialWithoutCachedMapping(string prefix, string literalName)
    {
        var unrelated = ObjectDisclosure(prefix, "\"private\"");
        var selected = ObjectDisclosure(literalName, "\"public\"");
        string[] digests = [Digest(unrelated), Digest(selected)];
        var signedPayload = new Dictionary<string, object>
        {
            ["exp"] = 4102444800L,
            ["_sd"] = digests
        };
        var issuerKey = RandomNumberGenerator.GetBytes(32);
        var jwt = new JwtSigner().CreateJwt(signedPayload, issuerKey, SignatureAlgorithm.HS256);
        var imported = new SdJwt(jwt, [unrelated, selected], HashAlgorithm.Sha256);

        // Exercises DisclosureClaimPathMapper.BuildClaimPathMapping, not an injected map.
        var presentation = new SdJwtPresenter().CreatePresentation(imported, [literalName]);

        string[] expected = [selected];
        Assert.Equal(expected, presentation.SelectedDisclosures);
    }

    [Fact]
    public void Should_IncludeGenuineParent_When_ImportingSignedNestedCredential()
    {
        var child = ObjectDisclosure("email", "\"shown\"");
        var parent = ObjectDisclosure("profile", NestedObject(Digest(child)));
        string[] digests = [Digest(parent)];
        var signedPayload = new Dictionary<string, object>
        {
            ["exp"] = 4102444800L,
            ["_sd"] = digests
        };
        var issuerKey = RandomNumberGenerator.GetBytes(32);
        var jwt = new JwtSigner().CreateJwt(signedPayload, issuerKey, SignatureAlgorithm.HS256);
        var imported = new SdJwt(jwt, [parent, child], HashAlgorithm.Sha256);

        var presentation = new SdJwtPresenter().CreatePresentation(imported, ["profile.email"]);

        string[] expected = [parent, child];
        Assert.Equal(expected, presentation.SelectedDisclosures);
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

        string[] expected = ["shipping"];
        Assert.Equal(expected, presentation.SelectedDisclosures);
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

        string[] expected = ["root"];
        Assert.Equal(expected, presentation.SelectedDisclosures);
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

        string[] expected = ["email"];
        Assert.Equal(expected, presentation.SelectedDisclosures);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void Should_RejectCollidingImportedClaimPaths_When_LiteralNameMimicsNestedPath(bool isArray, bool literalFirst)
    {
        var child = isArray
            ? ArrayDisclosure("\"public\"")
            : ObjectDisclosure("email", "\"public\"");
        var parent = isArray
            ? ObjectDisclosure("records", $"[null,{ArrayPlaceholder(Digest(child))}]")
            : ObjectDisclosure("profile", NestedObject(Digest(child)));
        var literal = isArray
            ? ObjectDisclosure("records[1]", "\"secret\"")
            : ObjectDisclosure("profile.email", "\"secret\"");

        string[] rootDigests = literalFirst
            ? [Digest(literal), Digest(parent)]
            : [Digest(parent), Digest(literal)];
        var signedPayload = new Dictionary<string, object>
        {
            ["exp"] = 4102444800L,
            ["_sd"] = rootDigests
        };
        var jwt = new JwtSigner().CreateJwt(signedPayload, RandomNumberGenerator.GetBytes(32), SignatureAlgorithm.HS256);
        var imported = new SdJwt(jwt, [parent, child, literal], HashAlgorithm.Sha256);

        // Imported credentials have no issuer-supplied claim-path mapping. A literal
        // dotted/bracketed name can collide with a true nested object's path.
        var requestedPath = isArray ? "records[1]" : "profile.email";
        var exception = Assert.Throws<InvalidOperationException>(() =>
            new SdJwtPresenter().CreatePresentation(imported, [requestedPath]));

        Assert.Contains("Ambiguous claim path", exception.Message, StringComparison.Ordinal);
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
