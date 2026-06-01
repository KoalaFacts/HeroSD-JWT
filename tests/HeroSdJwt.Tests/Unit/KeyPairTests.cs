using HeroSdJwt.Primitives;

namespace HeroSdJwt.Tests.Unit;

/// <summary>
/// Tests for the <see cref="KeyPair"/> value type, including its construction guards
/// and tuple deconstruction support.
/// </summary>
public class KeyPairTests
{
    [Fact]
    public void Constructor_WithValidKeys_StoresKeys()
    {
        byte[] priv = [1, 2, 3];
        byte[] pub = [4, 5, 6];

        var pair = new KeyPair(priv, pub);

        Assert.Same(priv, pair.PrivateKey);
        Assert.Same(pub, pair.PublicKey);
    }

    [Fact]
    public void Constructor_WithNullPrivateKey_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new KeyPair(null!, [1]));
    }

    [Fact]
    public void Constructor_WithNullPublicKey_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new KeyPair([1], null!));
    }

    [Fact]
    public void Constructor_WithEmptyPrivateKey_Throws()
    {
        var ex = Assert.Throws<ArgumentException>(() => new KeyPair([], [1]));
        Assert.Equal("privateKey", ex.ParamName);
    }

    [Fact]
    public void Constructor_WithEmptyPublicKey_Throws()
    {
        var ex = Assert.Throws<ArgumentException>(() => new KeyPair([1], []));
        Assert.Equal("publicKey", ex.ParamName);
    }

    [Fact]
    public void Deconstruct_ReturnsBothKeys()
    {
        byte[] priv = [7, 8];
        byte[] pub = [9, 10];
        var pair = new KeyPair(priv, pub);

        var (deconstructedPrivate, deconstructedPublic) = pair;

        Assert.Same(priv, deconstructedPrivate);
        Assert.Same(pub, deconstructedPublic);
    }
}
