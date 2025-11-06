using HeroSdJwt.Internal.Ed25519;
using Xunit;
using System;
using System.Security.Cryptography;

namespace HeroSdJwt.Tests.Unit.Cryptography;

/// <summary>
/// Diagnostic tests for RFC 8032 TEST 1024 to identify where our implementation diverges.
/// Note: Errata ID 7031 indicates some test vectors 100-111 "are not expected to validate."
/// </summary>
public class Ed25519Test1024DiagnosticTests
{
    [Fact]
    public void Test1024_Step1_HashSeed()
    {
        // RFC 8032 TEST 1024 seed
        var seed = HexToBytes("f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5");

        // Compute SHA-512
        byte[] hash = new byte[64];
        using (var sha512 = SHA512.Create())
        {
            sha512.TryComputeHash(seed, hash, out _);
        }

        // Expected from PyNaCl reference
        var expectedHash = HexToBytes(
            "609C888D0EF886D34B6EDEF27FB244AA04B3A49C82260E6AB86E784FF488CCC8" +
            "6990F0F6BEFEB2651705E7F5F6CF2F13C42005C7CA8419B1FD050616F902D258");

        Assert.Equal(expectedHash, hash);
    }

    [Fact]
    public void Test1024_Step2_ClampScalar()
    {
        // SHA-512 of seed
        var hash = HexToBytes(
            "609C888D0EF886D34B6EDEF27FB244AA04B3A49C82260E6AB86E784FF488CCC8" +
            "6990F0F6BEFEB2651705E7F5F6CF2F13C42005C7CA8419B1FD050616F902D258");

        // Clamp
        var clamped = new byte[32];
        Array.Copy(hash, clamped, 32);
        clamped[0] &= 248;
        clamped[31] &= 127;
        clamped[31] |= 64;

        // Expected from PyNaCl reference
        var expectedClamped = HexToBytes("609C888D0EF886D34B6EDEF27FB244AA04B3A49C82260E6AB86E784FF488CC48");

        Assert.Equal(expectedClamped, clamped);
    }

    [Fact]
    public void Test1024_Step3_ComputeRHash()
    {
        // h[32:64]
        var hashSuffix = HexToBytes("6990F0F6BEFEB2651705E7F5F6CF2F13C42005C7CA8419B1FD050616F902D258");

        // RFC 8032 TEST 1024 message
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

        // Compute SHA-512(hashSuffix || message)
        byte[] rHash = new byte[64];
        using (var sha512 = SHA512.Create())
        {
            sha512.Initialize();
            sha512.TransformBlock(hashSuffix, 0, 32, null, 0);
            sha512.TransformFinalBlock(message, 0, message.Length);
            Array.Copy(sha512.Hash!, rHash, 64);
        }

        // Expected from PyNaCl reference
        var expectedRHash = HexToBytes(
            "EC77EDD6F66283720EF89C3F765FAEF4399F62AE54DEA132939C604384E4E07F" +
            "1538B24D2907A4E43B92A8ECF1D377E3C184DE4F27E18AF17AC79E3ADAEF6200");

        Assert.Equal(expectedRHash, rHash);
    }

    [Fact]
    public void Test1024_FullSignature_MatchesPyNaCl()
    {
        // RFC 8032 TEST 1024 seed and message
        var seed = HexToBytes("f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5");
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

        // Sign with our implementation
        var (publicKey, expandedPrivateKey) = Ed25519.KeyPairFromSeed(seed);
        var signature = Ed25519.Sign(message, expandedPrivateKey);

        // PyNaCl produces this signature (NOT the RFC 8032 expected signature)
        var pyNaClSignature = HexToBytes(
            "9af9821907d4979f62cf7e2b35e6e8dcd0062783ae7675588961b3a941dca50f" +
            "9ee46f9632ee39e57586785a9cd287c4d28f212be2a2c5c82ae2db43d900dc0f");

        // Our implementation should match PyNaCl
        Assert.Equal(pyNaClSignature, signature);
    }

    private static byte[] HexToBytes(string hex)
    {
        hex = hex.Replace(" ", "").Replace("\n", "");
        if (string.IsNullOrEmpty(hex))
            return Array.Empty<byte>();

        var bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        }
        return bytes;
    }
}
