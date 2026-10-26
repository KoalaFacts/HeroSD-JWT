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
    public void Should_RejectOversizedImportedJwtBeforeDecoding()
    {
        var jwt = "eyJhbGciOiJIUzI1NiJ9.e30." + new string('a', Constants.MAX_JWT_SIZE_BYTES);
        var imported = new SdJwt(jwt, [], HashAlgorithm.Sha256);

        var exception = Assert.Throws<ArgumentException>(() =>
            new DisclosureClaimPathMapper().BuildClaimPathMapping(imported));

        Assert.Contains("maximum allowed size", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Should_NotTreatMultiPropertyArrayObjectAsDisclosurePlaceholder()
    {
        var disclosure = Base64UrlEncoder.Encode(/*lang=json,strict*/ "[\"salt\",\"secret\"]");
        var digest = new DigestCalculator().ComputeDigest(disclosure, HashAlgorithm.Sha256);
        var imported = CreateSignedCredential($"[{{\"...\":\"{digest}\",\"public\":true}}]", disclosure);
        var mapper = new DisclosureClaimPathMapper();

        var mapping = mapper.BuildClaimPathMapping(imported);

        Assert.DoesNotContain("items[0]", mapping.Keys);
        _ = Assert.Throws<ArgumentException>(() =>
            new SdJwtPresenter(mapper).CreatePresentation(imported, ["items[0]"]));
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
