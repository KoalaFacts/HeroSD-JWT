using HeroSdJwt.Internal.Ed25519;

namespace HeroSdJwt.Tests.Unit.Cryptography;

/// <summary>
/// Negative, argument-validation, and edge-case tests for the hand-rolled Ed25519 implementation.
/// The RFC 8032 known-answer vectors (see <see cref="Ed25519Rfc8032Tests"/>) prove the happy path;
/// these tests exercise the rejection paths that matter for a signature primitive: malformed inputs,
/// signature/message tampering, and the input-length guards on the public API.
/// </summary>
public class Ed25519NegativeTests
{
    private static readonly byte[] Seed =
        Convert.FromHexString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");

    [Fact]
    public void Verify_WithNullArguments_Throws()
    {
        var (publicKey, expandedPrivateKey) = Ed25519.KeyPairFromSeed(Seed);
        var signature = Ed25519.Sign([1, 2, 3], expandedPrivateKey);

        Assert.Throws<ArgumentNullException>(() => Ed25519.Verify(null!, [1, 2, 3], publicKey));
        Assert.Throws<ArgumentNullException>(() => Ed25519.Verify(signature, null!, publicKey));
        Assert.Throws<ArgumentNullException>(() => Ed25519.Verify(signature, [1, 2, 3], null!));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(63)]
    [InlineData(65)]
    [InlineData(128)]
    public void Verify_WithWrongSignatureLength_Throws(int length)
    {
        var (publicKey, _) = Ed25519.KeyPairFromSeed(Seed);

        Assert.Throws<ArgumentException>(() => Ed25519.Verify(new byte[length], [1, 2, 3], publicKey));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(31)]
    [InlineData(33)]
    [InlineData(64)]
    public void Verify_WithWrongPublicKeyLength_Throws(int length)
    {
        var signature = new byte[Ed25519.SIGNATURE_SIZE_IN_BYTES];

        Assert.Throws<ArgumentException>(() => Ed25519.Verify(signature, [1, 2, 3], new byte[length]));
    }

    [Fact]
    public void Sign_WithNullArguments_Throws()
    {
        var (_, expandedPrivateKey) = Ed25519.KeyPairFromSeed(Seed);

        Assert.Throws<ArgumentNullException>(() => Ed25519.Sign(null!, expandedPrivateKey));
        Assert.Throws<ArgumentNullException>(() => Ed25519.Sign([1, 2, 3], null!));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(32)]
    [InlineData(63)]
    [InlineData(65)]
    public void Sign_WithWrongPrivateKeyLength_Throws(int length)
    {
        Assert.Throws<ArgumentException>(() => Ed25519.Sign([1, 2, 3], new byte[length]));
    }

    [Fact]
    public void KeyPairFromSeed_WithNullOrWrongLengthSeed_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => Ed25519.KeyPairFromSeed(null!));
        Assert.Throws<ArgumentException>(() => Ed25519.KeyPairFromSeed(new byte[31]));
        Assert.Throws<ArgumentException>(() => Ed25519.KeyPairFromSeed(new byte[33]));
    }

    [Fact]
    public void PublicKeyFromSeed_MatchesKeyPairFromSeed()
    {
        var publicKey = Ed25519.PublicKeyFromSeed(Seed);
        var (expectedPublicKey, _) = Ed25519.KeyPairFromSeed(Seed);

        Assert.Equal(expectedPublicKey, publicKey);
    }

    [Fact]
    public void PublicKeyFromSeed_WithNullOrWrongLengthSeed_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => Ed25519.PublicKeyFromSeed(null!));
        Assert.Throws<ArgumentException>(() => Ed25519.PublicKeyFromSeed(new byte[16]));
    }

    [Fact]
    public void Verify_WhenMessageTampered_ReturnsFalse()
    {
        var (publicKey, expandedPrivateKey) = Ed25519.KeyPairFromSeed(Seed);
        var message = new byte[] { 1, 2, 3, 4, 5 };
        var signature = Ed25519.Sign(message, expandedPrivateKey);

        message[2] ^= 0xFF; // flip a bit in the message

        Assert.False(Ed25519.Verify(signature, message, publicKey));
    }

    [Fact]
    public void Verify_WhenEveryByteOfSignatureFlipped_AllFail()
    {
        // A robust verifier must reject any single-byte corruption across the whole 64-byte signature,
        // including the S (scalar) half where malleability bugs typically hide.
        var (publicKey, expandedPrivateKey) = Ed25519.KeyPairFromSeed(Seed);
        var message = new byte[] { 10, 20, 30 };
        var signature = Ed25519.Sign(message, expandedPrivateKey);

        for (int i = 0; i < signature.Length; i++)
        {
            var tampered = (byte[])signature.Clone();
            tampered[i] ^= 0x01;
            Assert.False(Ed25519.Verify(tampered, message, publicKey),
                $"Signature with byte {i} flipped must fail verification");
        }
    }

    [Fact]
    public void Verify_WithAllZeroSignature_ReturnsFalse()
    {
        var (publicKey, _) = Ed25519.KeyPairFromSeed(Seed);

        Assert.False(Ed25519.Verify(new byte[Ed25519.SIGNATURE_SIZE_IN_BYTES], [1, 2, 3], publicKey));
    }

    [Fact]
    public void Verify_WithAllZeroPublicKey_ReturnsFalse()
    {
        var (_, expandedPrivateKey) = Ed25519.KeyPairFromSeed(Seed);
        var message = new byte[] { 1, 2, 3 };
        var signature = Ed25519.Sign(message, expandedPrivateKey);

        // All-zero is not a valid curve point encoding; verification must not succeed.
        Assert.False(Ed25519.Verify(signature, message, new byte[Ed25519.PUBLIC_KEY_SIZE_IN_BYTES]));
    }

    [Fact]
    public void Sign_IsDeterministic_ForSameKeyAndMessage()
    {
        // Ed25519 signatures are deterministic per RFC 8032.
        var (_, expandedPrivateKey) = Ed25519.KeyPairFromSeed(Seed);
        var message = new byte[] { 9, 8, 7, 6 };

        var s1 = Ed25519.Sign(message, expandedPrivateKey);
        var s2 = Ed25519.Sign(message, expandedPrivateKey);

        Assert.Equal(s1, s2);
    }

    [Fact]
    public void Verify_AcceptsEmptyMessage()
    {
        var (publicKey, expandedPrivateKey) = Ed25519.KeyPairFromSeed(Seed);
        var signature = Ed25519.Sign([], expandedPrivateKey);

        Assert.True(Ed25519.Verify(signature, [], publicKey));
    }
}
