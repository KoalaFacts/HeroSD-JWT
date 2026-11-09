using HeroSdJwt.Encoding;
using HeroSdJwt.Exceptions;
using HeroSdJwt.Issuance;
using HeroSdJwt.Models;
using HeroSdJwt.Presentation;
using HeroSdJwt.Primitives;
using System.Security.Cryptography;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Imported SD-JWTs must not cause unbounded holder-side parsing allocations
/// or expose disclosure paths for non-canonical array references.
/// </summary>
public class HolderClaimPathMappingTests
{
    private static readonly byte[] _signingKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    [Fact]
    public void Should_RejectCompactJwtSeparatorFloodWithoutProportionalAllocations()
    {
        // Under the verifier's size limit, but an unbounded Split('.') creates
        // over 55,000 array entries before rejecting this malformed token.
        var imported = new SdJwt(new string('.', 55_000), [], HashAlgorithm.Sha256);
        Assert.True(imported.Jwt.Length < Constants.MAX_JWT_SIZE_BYTES);
        var mapper = new DisclosureClaimPathMapper();

        void Reject()
        {
            var exception = Assert.Throws<ArgumentException>(() => mapper.BuildClaimPathMapping(imported));
            Assert.Contains("Invalid JWT format", exception.Message, StringComparison.Ordinal);
        }

        Reject(); // Warm the assertion and exception path.
        var before = GC.GetAllocatedBytesForCurrentThread();
        for (var i = 0; i < 12; i++)
        {
            Reject();
        }

        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.True(allocated < 500_000, $"Holder-side separator flood allocated {allocated} bytes");
    }

    [Fact]
    public void Should_ContinueMappingLargeSignedPayloadForIssuerCompatibility()
    {
        var disclosure = Base64UrlEncoder.Encode(/*lang=json,strict*/ "[\"salt\",\"degree\"]");
        var digest = new DigestCalculator().ComputeDigest(disclosure, HashAlgorithm.Sha256);
        var padding = new string('x', Constants.MAX_JWT_SIZE_BYTES);
        var imported = CreateSignedCredential(
            $"[{{\"...\":\"{digest}\"}},{{\"permanent\":\"{padding}\"}}]",
            disclosure);
        Assert.True(imported.Jwt.Length > Constants.MAX_JWT_SIZE_BYTES);

        var mapping = new DisclosureClaimPathMapper().BuildClaimPathMapping(imported);

        Assert.Equal(0, mapping["items[0]"]);
    }

    [Fact]
    public void Should_RejectMultiPropertyArrayObjectWithReservedPlaceholder()
    {
        // RFC 9901 permits "..." only as the sole member of an array slot.
        var disclosure = Base64UrlEncoder.Encode(/*lang=json,strict*/ "[\"salt\",\"secret\"]");
        var digest = new DigestCalculator().ComputeDigest(disclosure, HashAlgorithm.Sha256);
        var imported = CreateSignedCredential($"[{{\"...\":\"{digest}\",\"public\":true}}]", disclosure);

        _ = Assert.Throws<MalformedDisclosureException>(() =>
            new DisclosureClaimPathMapper().BuildClaimPathMapping(imported));
    }

    [Theory]
    [InlineData("\"...\":\"opaque\"")]
    [InlineData("\"profile\":{\"...\":\"opaque\"}")]
    [InlineData("\"records\":[{\"profile\":{\"...\":\"opaque\"}}]")]
    public void Should_RejectReservedPlaceholderOutsideArraySlotBeforeMapping(string payloadMember)
    {
        // The signed payload is not a valid SD-JWT structure even without a
        // matching Disclosure; the holder must not silently skip this member.
        var imported = CreateSignedPayload($"{{\"exp\":4102444800,{payloadMember}}}");

        _ = Assert.Throws<MalformedDisclosureException>(() =>
            new DisclosureClaimPathMapper().BuildClaimPathMapping(imported));
    }

    [Theory]
    [InlineData(/*lang=json,strict*/ "{\"...\":null}")]
    [InlineData(/*lang=json,strict*/ "{\"...\":false}")]
    [InlineData(/*lang=json,strict*/ "{\"...\":\"digest\",\"public\":true}")]
    public void Should_RejectMalformedArrayPlaceholderBeforeMapping(string arrayItem)
    {
        var imported = CreateSignedPayload($"{{\"exp\":4102444800,\"items\":[{arrayItem}]}}");

        _ = Assert.Throws<MalformedDisclosureException>(() =>
            new DisclosureClaimPathMapper().BuildClaimPathMapping(imported));
    }

    [Fact]
    public void Should_RejectReservedPlaceholderInsideReferencedDisclosureValue()
    {
        var disclosure = Base64UrlEncoder.Encode(
            /*lang=json,strict*/ "[\"salt\",\"profile\",{\"...\":\"opaque\"}]");
        var digest = new DigestCalculator().ComputeDigest(disclosure, HashAlgorithm.Sha256);
        var imported = CreateSignedPayload($"{{\"exp\":4102444800,\"_sd\":[\"{digest}\"]}}", disclosure);

        _ = Assert.Throws<MalformedDisclosureException>(() =>
            new DisclosureClaimPathMapper().BuildClaimPathMapping(imported));
    }

    [Theory]
    [InlineData("null")]
    [InlineData("false")]
    [InlineData("42")]
    [InlineData("\"digest\"")]
    [InlineData("{}")]
    [InlineData("[null]")]
    [InlineData("[42]")]
    [InlineData("[{}]")]
    [InlineData("[\"digest\",null]")]
    public void Should_RejectMalformedObjectDigestMetadataBeforeMapping(string invalidSd)
    {
        // This issuer JWT is correctly signed. A holder must not silently
        // ignore malformed _sd metadata when deriving disclosure paths.
        var imported = CreateSignedPayload($"{{\"exp\":4102444800,\"_sd\":{invalidSd}}}");

        _ = Assert.Throws<MalformedDisclosureException>(() =>
            new DisclosureClaimPathMapper().BuildClaimPathMapping(imported));
    }

    [Theory]
    [InlineData("null")]
    [InlineData("[false]")]
    public void Should_RejectMalformedNestedObjectDigestMetadataBeforeMapping(string invalidSd)
    {
        var imported = CreateSignedPayload($"{{\"exp\":4102444800,\"profile\":{{\"_sd\":{invalidSd}}}}}");

        _ = Assert.Throws<MalformedDisclosureException>(() =>
            new DisclosureClaimPathMapper().BuildClaimPathMapping(imported));
    }

    [Fact]
    public void Should_ContinueMappingValidSignedObjectDigest()
    {
        var disclosure = Base64UrlEncoder.Encode(/*lang=json,strict*/ """["salt","email","alice@example.test"]""");
        var digest = new DigestCalculator().ComputeDigest(disclosure, HashAlgorithm.Sha256);
        var imported = CreateSignedPayload($"{{\"exp\":4102444800,\"_sd\":[\"{digest}\"]}}", disclosure);

        var mapping = new DisclosureClaimPathMapper().BuildClaimPathMapping(imported);

        Assert.Equal(0, mapping["email"]);
    }

    [Fact]
    public void Should_RejectObjectDisclosureInArrayPlaceholder()
    {
        var disclosure = Base64UrlEncoder.Encode(/*lang=json,strict*/ "[\"salt\",\"name\",\"secret\"]");
        var digest = new DigestCalculator().ComputeDigest(disclosure, HashAlgorithm.Sha256);
        var imported = CreateSignedCredential($"[{{\"...\":\"{digest}\"}}]", disclosure);

        _ = Assert.Throws<MalformedDisclosureException>(() =>
            new DisclosureClaimPathMapper().BuildClaimPathMapping(imported));
    }

    [Fact]
    public void Should_RejectArrayDisclosureReferencedByObjectDigest()
    {
        // An object _sd digest must refer to [salt, name, value], not the
        // two-element [salt, value] form used by array placeholders.
        var disclosure = Base64UrlEncoder.Encode(/*lang=json,strict*/ """["salt","private"]""");
        var digest = new DigestCalculator().ComputeDigest(disclosure, HashAlgorithm.Sha256);
        var header = Base64UrlEncoder.Encode(/*lang=json,strict*/ """{"alg":"HS256"}""");
        var payload = Base64UrlEncoder.Encode(
            $"{{\"exp\":4102444800,\"_sd\":[\"{digest}\"]}}");
        var signingInput = $"{header}.{payload}";
        var signature = HMACSHA256.HashData(_signingKey, System.Text.Encoding.UTF8.GetBytes(signingInput));
        var imported = new SdJwt(
            $"{signingInput}.{Base64UrlEncoder.Encode(signature)}",
            [disclosure],
            HashAlgorithm.Sha256);

        _ = Assert.Throws<MalformedDisclosureException>(() =>
            new DisclosureClaimPathMapper().BuildClaimPathMapping(imported));
    }

    [Fact]
    public void Should_ContinueMappingCanonicalSignedArrayDisclosure()
    {
        var disclosure = Base64UrlEncoder.Encode(/*lang=json,strict*/ "[\"salt\",\"degree\"]");
        var digest = new DigestCalculator().ComputeDigest(disclosure, HashAlgorithm.Sha256);
        var imported = CreateSignedCredential($"[{{\"...\":\"{digest}\"}}]", disclosure);
        var mapper = new DisclosureClaimPathMapper();

        var mapping = mapper.BuildClaimPathMapping(imported);
        var presentation = new SdJwtPresenter(mapper).CreatePresentation(imported, ["items[0]"]);

        Assert.Equal(0, mapping["items[0]"]);
        Assert.Equal(disclosure, Assert.Single(presentation.SelectedDisclosures));
    }

    [Theory]
    [InlineData(/*lang=json,strict*/ "{\"exp\":4102444800,\"profile\":{\"_sd_alg\":\"sha-512\"}}")]
    [InlineData(/*lang=json,strict*/ "{\"exp\":4102444800,\"roles\":[{\"_sd_alg\":null}]}")]
    public void Should_RejectNestedSdAlgInSignedPayloadBeforeMapping(string payloadJson)
    {
        // RFC 9901 reserves _sd_alg for the root issuer payload. The verifier
        // rejects nested instances, so holder-side mapping must not ignore them.
        var imported = CreateSignedPayload(payloadJson);

        _ = Assert.Throws<MalformedDisclosureException>(() =>
            new DisclosureClaimPathMapper().BuildClaimPathMapping(imported));
    }

    [Fact]
    public void Should_RejectNestedSdAlgInReferencedDisclosureBeforeMapping()
    {
        var disclosure = Base64UrlEncoder.Encode(
            /*lang=json,strict*/ "[\"salt\",\"profile\",{\"_sd_alg\":\"sha-256\"}]");
        var digest = new DigestCalculator().ComputeDigest(disclosure, HashAlgorithm.Sha256);
        var imported = CreateSignedPayload($"{{\"exp\":4102444800,\"_sd\":[\"{digest}\"]}}", disclosure);

        _ = Assert.Throws<MalformedDisclosureException>(() =>
            new DisclosureClaimPathMapper().BuildClaimPathMapping(imported));
    }

    [Fact]
    public void Should_ContinueMappingRootSdAlgWithValidDisclosure()
    {
        var disclosure = Base64UrlEncoder.Encode(
            /*lang=json,strict*/ "[\"salt\",\"profile\",{\"name\":\"Alice\"}]");
        var digest = new DigestCalculator().ComputeDigest(disclosure, HashAlgorithm.Sha256);
        var imported = CreateSignedPayload(
            $"{{\"exp\":4102444800,\"_sd_alg\":\"sha-256\",\"_sd\":[\"{digest}\"]}}",
            disclosure);

        var mapping = new DisclosureClaimPathMapper().BuildClaimPathMapping(imported);

        Assert.Equal(0, mapping["profile"]);
    }

    [Theory]
    [InlineData("null")]
    [InlineData("false")]
    [InlineData("42")]
    [InlineData("\"md5\"")]
    [InlineData("\"SHA-256\"")]
    public void Should_RejectMalformedRootHashAlgorithmBeforeMapping(string algorithmJson)
    {
        var imported = CreateSignedPayload(
            $"{{\"exp\":4102444800,\"_sd_alg\":{algorithmJson}}}");

        _ = Assert.Throws<MalformedDisclosureException>(() =>
            new DisclosureClaimPathMapper().BuildClaimPathMapping(imported));
    }

    [Fact]
    public void Should_RejectHashAlgorithmMismatchBetweenSignedPayloadAndImportedMetadata()
    {
        var imported = CreateSignedPayload(
            /*lang=json,strict*/ """{"exp":4102444800,"_sd_alg":"sha-512"}""");

        _ = Assert.Throws<MalformedDisclosureException>(() =>
            new DisclosureClaimPathMapper().BuildClaimPathMapping(imported));
    }

    [Theory]
    [InlineData(HashAlgorithm.Sha384, "sha-384")]
    [InlineData(HashAlgorithm.Sha512, "sha-512")]
    public void Should_ContinueMappingMatchingNonDefaultHashAlgorithm(
        HashAlgorithm algorithm, string algorithmName)
    {
        var disclosure = Base64UrlEncoder.Encode(
            /*lang=json,strict*/ """["salt","email","alice@example.test"]""");
        var digest = new DigestCalculator().ComputeDigest(disclosure, algorithm);
        var signed = CreateSignedPayload(
            $"{{\"exp\":4102444800,\"_sd_alg\":\"{algorithmName}\",\"_sd\":[\"{digest}\"]}}",
            disclosure);
        var imported = new SdJwt(signed.Jwt, signed.Disclosures, algorithm);

        var mapping = new DisclosureClaimPathMapper().BuildClaimPathMapping(imported);

        Assert.Equal(0, mapping["email"]);
    }

    private static SdJwt CreateSignedPayload(string payloadJson, params string[] disclosures)
    {
        var header = Base64UrlEncoder.Encode(/*lang=json,strict*/ """{"alg":"HS256"}""");
        var payload = Base64UrlEncoder.Encode(payloadJson);
        var signingInput = $"{header}.{payload}";
        var signature = HMACSHA256.HashData(_signingKey, System.Text.Encoding.UTF8.GetBytes(signingInput));
        return new SdJwt(
            $"{signingInput}.{Base64UrlEncoder.Encode(signature)}",
            disclosures,
            HashAlgorithm.Sha256);
    }

    private static SdJwt CreateSignedCredential(string itemsJson, string disclosure)
    {
        var header = Base64UrlEncoder.Encode(/*lang=json,strict*/ "{\"alg\":\"HS256\"}");
        var payload = Base64UrlEncoder.Encode($"{{\"exp\":4102444800,\"items\":{itemsJson}}}");
        var signingInput = $"{header}.{payload}";
        var signature = HMACSHA256.HashData(_signingKey, System.Text.Encoding.UTF8.GetBytes(signingInput));
        var jwt = $"{signingInput}.{Base64UrlEncoder.Encode(signature)}";
        return new SdJwt(jwt, [disclosure], HashAlgorithm.Sha256);
    }
}
