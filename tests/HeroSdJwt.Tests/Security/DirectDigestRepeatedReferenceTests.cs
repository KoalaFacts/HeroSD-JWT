using HeroSdJwt.Encoding;
using HeroSdJwt.Issuance;
using HeroSdJwt.Models;
using HeroSdJwt.Verification;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// RFC 9901 Section 7.1 rejects any digest referenced more than once,
/// including references to undisclosed claims and equivalent digest encodings.
/// </summary>
public sealed class DirectDigestRepeatedReferenceTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Should_RejectRepeatedExpectedDigest_WhenValidDisclosureIsPresent(bool paddedAlias)
    {
        var disclosure = Base64UrlEncoder.Encode("[\\\"salt\\\",\\\"email\\\",\\\"alice@example.test\\\"]");
        var digest = new Digest(
            new DigestCalculator().ComputeDigest(disclosure, HashAlgorithm.Sha256),
            HashAlgorithm.Sha256);
        var repeated = paddedAlias
            ? new Digest(digest.Value + "=", HashAlgorithm.Sha256)
            : digest;

        Assert.False(new DigestValidator().ValidateAllDigests(
            [disclosure],
            [digest, repeated],
            HashAlgorithm.Sha256));
    }

    [Fact]
    public void Should_RejectRepeatedDecoyDigest_WhenExpectedLookupIsIndexed()
    {
        var calculator = new DigestCalculator();
        var disclosures = Enumerable.Range(0, 8)
            .Select(i => Base64UrlEncoder.Encode($"[\\\"salt-{i}\\\",\\\"claim-{i}\\\",\\\"value-{i}\\\"]"))
            .ToArray();

        var expected = disclosures.Select(d => new Digest(
            calculator.ComputeDigest(d, HashAlgorithm.Sha256),
            HashAlgorithm.Sha256)).ToList();
        var decoy = new Digest(
            calculator.ComputeDigest("decoy-reference", HashAlgorithm.Sha256),
            HashAlgorithm.Sha256);
        expected.AddRange(Enumerable.Range(0, 32).Select(i => new Digest(
            calculator.ComputeDigest($"other-decoy-{i}", HashAlgorithm.Sha256),
            HashAlgorithm.Sha256)));
        expected.Add(decoy);
        expected.Add(new Digest(decoy.Value + "=", HashAlgorithm.Sha256));

        Assert.False(new DigestValidator(calculator).ValidateAllDigests(
            disclosures,
            expected,
            HashAlgorithm.Sha256));
    }
}
