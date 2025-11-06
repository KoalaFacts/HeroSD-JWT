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
    /// RFC 8032 Test Vector - TEST 1024 (1023 byte message)
    /// </summary>
    [Fact]
    public void Ed25519_Rfc8032_TestVector_LongMessage()
    {
        // SECRET KEY
        var seed = HexToBytes("f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5");

        // PUBLIC KEY (expected)
        var expectedPublicKey = HexToBytes("278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e");

        // MESSAGE (1023 bytes from RFC 8032 TEST 1024)
        var message = HexToBytes(
            "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8" +
            "79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc" +
            "1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4feba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e" +
            "06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbeffefd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec" +
            "7aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed185ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb" +
            "2d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f27" +
            "088d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b0" +
            "707e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128bab27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51" +
            "addd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429ec96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb" +
            "751fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff" +
            "8ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dfff7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e" +
            "08d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49" +
            "e488acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a32ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d9" +
            "7e6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5fb93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506" +
            "b50d334ba77c225bc307ba537152f3f161f0e4eafe595f6d9d90d11faa933a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937" +
            "380db2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b");

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
        var message = HexToBytes("74657374"); // "test" in hex

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
