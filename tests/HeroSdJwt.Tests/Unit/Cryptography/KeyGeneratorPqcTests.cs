using HeroSdJwt.Cryptography;

namespace HeroSdJwt.Tests.Unit.Cryptography;

/// <summary>
/// Tests for the guard clauses and the not-yet-implemented post-quantum paths of
/// <see cref="KeyGenerator"/>. These cover the failure branches that the happy-path
/// generation tests do not reach.
/// </summary>
public class KeyGeneratorPqcTests
{
    private readonly KeyGenerator _sut = new();

    [Theory]
    [InlineData(0)]
    [InlineData(-8)]
    [InlineData(100)] // not a multiple of 8
    public void GenerateHmacKey_WithInvalidBits_Throws(int bits)
    {
        Assert.Throws<ArgumentException>(() => _sut.GenerateHmacKey(bits));
    }

    [Fact]
    public void GenerateRsaKeyPair_BelowMinimumSize_Throws()
    {
        var ex = Assert.Throws<ArgumentException>(() => _sut.GenerateRsaKeyPair(1024));
        Assert.Equal("keySizeBits", ex.ParamName);
    }

    [Fact]
    public void GenerateMlDsa65KeyPair_IsNotYetSupported()
    {
        // ML-DSA (post-quantum) generation is a placeholder pending PQC API support.
        // It must throw rather than silently return an invalid/empty key pair.
        Assert.ThrowsAny<Exception>(() => _sut.GenerateMlDsa65KeyPair());
    }

    [Fact]
    public void GenerateMlDsa87KeyPair_IsNotYetSupported()
    {
        Assert.ThrowsAny<Exception>(() => _sut.GenerateMlDsa87KeyPair());
    }

    [Fact]
    public void Instance_IsUsable()
    {
        var key = KeyGenerator.Instance.GenerateHmacKey(256);
        Assert.Equal(32, key.Length);
    }
}
