using HeroSdJwt.Internal.Ed25519;
using Xunit;

namespace HeroSdJwt.Tests.Unit.Cryptography;

/// <summary>
/// Verification tests using official RFC 8032 test vectors for Ed25519.
/// These test vectors ensure our implementation produces identical results
/// to the standard specification.
/// </summary>
public class Ed25519Rfc8032Tests
{
    /// <summary>
    /// RFC 8032 Test Vector 1 - Basic signature test
    /// </summary>
    [Fact]
    public void Ed25519_Rfc8032_TestVector1_SignAndVerify()
    {
        // Test vector from RFC 8032 Section 7.1
        // SECRET KEY (32 bytes seed)
        var seed = HexToBytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");

        // PUBLIC KEY (expected)
        var expectedPublicKey = HexToBytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");

        // MESSAGE
        var message = HexToBytes("");

        // EXPECTED SIGNATURE
        var expectedSignature = HexToBytes(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");

        // Test key generation
        var (publicKey, expandedPrivateKey) = Ed25519.KeyPairFromSeed(seed);
        Assert.Equal(expectedPublicKey, publicKey);

        // Test signing
        var signature = Ed25519.Sign(message, expandedPrivateKey);
        Assert.Equal(expectedSignature, signature);

        // Test verification
        var isValid = Ed25519.Verify(signature, message, publicKey);
        Assert.True(isValid, "RFC 8032 Test Vector 1: Signature should verify");
    }

    /// <summary>
    /// RFC 8032 Test Vector 2 - Single byte message
    /// </summary>
    [Fact]
    public void Ed25519_Rfc8032_TestVector2_SingleByteMessage()
    {
        // SECRET KEY
        var seed = HexToBytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");

        // PUBLIC KEY (expected)
        var expectedPublicKey = HexToBytes("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");

        // MESSAGE
        var message = HexToBytes("72");

        // EXPECTED SIGNATURE
        var expectedSignature = HexToBytes(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" +
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");

        // Test
        var (publicKey, expandedPrivateKey) = Ed25519.KeyPairFromSeed(seed);
        Assert.Equal(expectedPublicKey, publicKey);

        var signature = Ed25519.Sign(message, expandedPrivateKey);
        Assert.Equal(expectedSignature, signature);

        var isValid = Ed25519.Verify(signature, message, publicKey);
        Assert.True(isValid, "RFC 8032 Test Vector 2: Signature should verify");
    }

    /// <summary>
    /// RFC 8032 Test Vector 3 - Two byte message
    /// </summary>
    [Fact]
    public void Ed25519_Rfc8032_TestVector3_TwoByteMessage()
    {
        // SECRET KEY
        var seed = HexToBytes("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");

        // PUBLIC KEY (expected)
        var expectedPublicKey = HexToBytes("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");

        // MESSAGE
        var message = HexToBytes("af82");

        // EXPECTED SIGNATURE
        var expectedSignature = HexToBytes(
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac" +
            "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a");

        // Test
        var (publicKey, expandedPrivateKey) = Ed25519.KeyPairFromSeed(seed);
        Assert.Equal(expectedPublicKey, publicKey);

        var signature = Ed25519.Sign(message, expandedPrivateKey);
        Assert.Equal(expectedSignature, signature);

        var isValid = Ed25519.Verify(signature, message, publicKey);
        Assert.True(isValid, "RFC 8032 Test Vector 3: Signature should verify");
    }

    /// <summary>
    /// RFC 8032 Test Vector - Longer message (1023 bytes)
    /// </summary>
    [Fact]
    public void Ed25519_Rfc8032_TestVector_LongMessage()
    {
        // SECRET KEY
        var seed = HexToBytes("f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5");

        // PUBLIC KEY (expected)
        var expectedPublicKey = HexToBytes("278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e");

        // MESSAGE (1023 bytes of 0x08, 0x..., 0xbf, 0x...)
        var message = new byte[1023];
        for (int i = 0; i < message.Length; i++)
        {
            message[i] = (byte)i;
        }

        // EXPECTED SIGNATURE
        var expectedSignature = HexToBytes(
            "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350" +
            "aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03");

        // Test
        var (publicKey, expandedPrivateKey) = Ed25519.KeyPairFromSeed(seed);
        Assert.Equal(expectedPublicKey, publicKey);

        var signature = Ed25519.Sign(message, expandedPrivateKey);
        Assert.Equal(expectedSignature, signature);

        var isValid = Ed25519.Verify(signature, message, publicKey);
        Assert.True(isValid, "RFC 8032 Long Message: Signature should verify");
    }

    /// <summary>
    /// Test that invalid signatures are properly rejected
    /// </summary>
    [Fact]
    public void Ed25519_InvalidSignature_ReturnsFalse()
    {
        var seed = HexToBytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        var message = HexToBytes("72");

        var (publicKey, expandedPrivateKey) = Ed25519.KeyPairFromSeed(seed);
        var signature = Ed25519.Sign(message, expandedPrivateKey);

        // Tamper with signature
        signature[0] ^= 0x01;

        var isValid = Ed25519.Verify(signature, message, publicKey);
        Assert.False(isValid, "Tampered signature should fail verification");
    }

    /// <summary>
    /// Test that signature verification fails with wrong public key
    /// </summary>
    [Fact]
    public void Ed25519_WrongPublicKey_ReturnsFalse()
    {
        var seed1 = HexToBytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        var seed2 = HexToBytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
        var message = HexToBytes("test");

        var (publicKey1, expandedPrivateKey1) = Ed25519.KeyPairFromSeed(seed1);
        var (publicKey2, _) = Ed25519.KeyPairFromSeed(seed2);

        var signature = Ed25519.Sign(message, expandedPrivateKey1);

        // Try to verify with wrong public key
        var isValid = Ed25519.Verify(signature, message, publicKey2);
        Assert.False(isValid, "Signature should fail with wrong public key");
    }

    /// <summary>
    /// Helper method to convert hex string to byte array
    /// </summary>
    private static byte[] HexToBytes(string hex)
    {
        if (hex.Length % 2 != 0)
            throw new ArgumentException("Hex string must have even length");

        var bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        }
        return bytes;
    }
}
