using HeroSdJwt.Primitives;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Tests.Security;

/// <summary>
/// Public protocol tables must not allow application code to change the
/// issuer's reserved-claim policy or its digest algorithm names globally.
/// </summary>
public class ProtocolConstantsMutationTests
{
    [Fact]
    public void Should_KeepReservedClaimsReadOnly_When_ExposedToConsumers()
    {
        Assert.Contains("exp", Constants.ReservedClaims);
        Assert.Contains("cnf", Constants.ReservedClaims);
        Assert.True(
            Constants.ReservedClaims is not ICollection<string> writable || writable.IsReadOnly,
            "ReservedClaims must not expose a mutable set.");
    }

    [Fact]
    public void Should_KeepHashAlgorithmNamesReadOnly_When_ExposedToConsumers()
    {
        Assert.Equal("sha-256", Constants.HashAlgorithmNames[HashAlgorithm.Sha256]);
        Assert.True(
            Constants.HashAlgorithmNames is not IDictionary<HashAlgorithm, string> writable || writable.IsReadOnly,
            "HashAlgorithmNames must not expose a mutable dictionary.");
    }

    [Fact]
    public void Should_KeepReverseHashAlgorithmNamesReadOnly_When_ExposedToConsumers()
    {
        Assert.Equal(HashAlgorithm.Sha256, Constants.HashAlgorithmFromName["sha-256"]);
        Assert.True(
            Constants.HashAlgorithmFromName is not IDictionary<string, HashAlgorithm> writable || writable.IsReadOnly,
            "HashAlgorithmFromName must not expose a mutable dictionary.");
    }
}
