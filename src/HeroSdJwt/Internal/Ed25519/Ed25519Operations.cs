// Ported from Chaos.NaCl (https://github.com/CodesInChaos/Chaos.NaCl)
// Original Author: Christian Winnerlein (CodesInChaos)
// Original Author: Dan Bernstein (djb) - Ref10 from SUPERCOP
// License: Public Domain
//
// Core Ed25519 cryptographic operations

using System;
using System.Security.Cryptography;

namespace HeroSdJwt.Internal.Ed25519;

/// <summary>
/// Core Ed25519 cryptographic operations.
///
/// Implements the three main Ed25519 operations:
/// - crypto_sign_keypair: Generate key pair from seed
/// - crypto_sign: Sign a message
/// - crypto_sign_verify: Verify a signature
/// </summary>
internal static class Ed25519Operations
{
    /// <summary>
    /// Generates an Ed25519 key pair from a 32-byte seed.
    ///
    /// Output:
    ///   pk[pkoffset..pkoffset+31]: 32-byte public key
    ///   sk[skoffset..skoffset+63]: 64-byte expanded private key
    /// Input:
    ///   seed[seedoffset..seedoffset+31]: 32-byte seed
    /// </summary>
    internal static void crypto_sign_keypair(
        byte[] pk, int pkoffset,
        byte[] sk, int skoffset,
        byte[] seed, int seedoffset)
    {
        // STEP 1: Hash the 32-byte seed with SHA-512 to get 64 bytes
        byte[] hash = new byte[64];
        using (var sha512 = SHA512.Create())
        {
            sha512.TryComputeHash(new ReadOnlySpan<byte>(seed, seedoffset, 32), hash, out _);
        }

        // STEP 2: Clamp the hash (first 32 bytes become secret scalar)
        hash[0] &= 248;
        hash[31] &= 127;
        hash[31] |= 64;

        // STEP 3: Perform scalar multiplication to get public key
        // pk = scalar * base_point
        GroupElementP3 A;
        GroupOperations.ge_scalarmult_base(out A, hash, 0);
        GroupOperations.ge_p3_tobytes(pk, pkoffset, ref A);

        // STEP 4: Store expanded private key (64 bytes)
        // sk[0..31] = original seed (for deterministic signing)
        // sk[32..63] = hash[32..63] (prefix for nonce generation)
        Array.Copy(seed, seedoffset, sk, skoffset, 32);
        Array.Copy(hash, 32, sk, skoffset + 32, 32);
    }

    /// <summary>
    /// Signs a message using Ed25519.
    ///
    /// Output:
    ///   sig[sigoffset..sigoffset+63]: 64-byte signature
    /// Input:
    ///   m[moffset..moffset+mlen-1]: Message to sign
    ///   sk[skoffset..skoffset+63]: 64-byte expanded private key
    /// </summary>
    internal static void crypto_sign(
        byte[] sig, int sigoffset,
        byte[] m, int moffset, int mlen,
        byte[] sk, int skoffset)
    {
        // STEP 1: Derive the secret scalar and public key from expanded key
        byte[] hash = new byte[64];
        using (var sha512 = SHA512.Create())
        {
            sha512.TryComputeHash(new ReadOnlySpan<byte>(sk, skoffset, 32), hash, out _);
        }

        // Clamp the secret scalar
        hash[0] &= 248;
        hash[31] &= 127;
        hash[31] |= 64;

        // Derive public key
        GroupElementP3 A;
        GroupOperations.ge_scalarmult_base(out A, hash, 0);
        byte[] publicKey = new byte[32];
        GroupOperations.ge_p3_tobytes(publicKey, 0, ref A);

        // STEP 2: Compute r = SHA-512(sk[32..63] || message)
        byte[] r = new byte[64];
        using (var sha512 = SHA512.Create())
        {
            sha512.Initialize();
            sha512.TransformBlock(sk, skoffset + 32, 32, null, 0);
            sha512.TransformFinalBlock(m, moffset, mlen);
            Array.Copy(sha512.Hash!, r, 64);
        }

        // Reduce r modulo L
        ScalarOperations.sc_reduce(r);

        // STEP 3: Compute R = r * base_point
        GroupElementP3 R;
        GroupOperations.ge_scalarmult_base(out R, r, 0);
        GroupOperations.ge_p3_tobytes(sig, sigoffset, ref R);

        // STEP 4: Compute k = SHA-512(R || public_key || message)
        byte[] hram = new byte[64];
        using (var sha512_2 = SHA512.Create())
        {
            sha512_2.Initialize();
            sha512_2.TransformBlock(sig, sigoffset, 32, null, 0); // R
            sha512_2.TransformBlock(publicKey, 0, 32, null, 0); // A
            sha512_2.TransformFinalBlock(m, moffset, mlen); // message
            Array.Copy(sha512_2.Hash!, hram, 64);
        }

        // Reduce k modulo L
        ScalarOperations.sc_reduce(hram);

        // STEP 5: Compute s = (r + k * private_scalar) mod L
        byte[] s_result = new byte[32];
        ScalarOperations.sc_muladd(s_result, hram, hash, r);
        Array.Copy(s_result, 0, sig, sigoffset + 32, 32);
    }

    /// <summary>
    /// Verifies an Ed25519 signature.
    ///
    /// Input:
    ///   sig[sigoffset..sigoffset+63]: 64-byte signature
    ///   m[moffset..moffset+mlen-1]: Signed message
    ///   pk[pkoffset..pkoffset+31]: 32-byte public key
    ///
    /// Returns: true if signature is valid, false otherwise
    /// </summary>
    internal static bool crypto_sign_verify(
        byte[] sig, int sigoffset,
        byte[] m, int moffset, int mlen,
        byte[] pk, int pkoffset)
    {
        // STEP 1: Check that s < L (prevent signature malleability)
        if ((sig[sigoffset + 63] & 224) != 0)
            return false;

        // Check if s >= L
        byte[] checkS = new byte[32];
        Array.Copy(sig, sigoffset + 32, checkS, 0, 32);
        if (!sc_isvalid(checkS))
            return false;

        // STEP 2: Decode public key
        GroupElementP3 A;
        if (!GroupOperations.ge_frombytes_negate_vartime(out A, pk, pkoffset))
            return false;

        // Negate A for the verification equation
        FieldOperations.fe_neg(out A.X, ref A.X);
        FieldOperations.fe_neg(out A.T, ref A.T);

        // STEP 3: Compute k = SHA-512(R || public_key || message)
        byte[] hram = new byte[64];
        using (var sha512 = SHA512.Create())
        {
            sha512.Initialize();
            sha512.TransformBlock(sig, sigoffset, 32, null, 0); // R
            sha512.TransformBlock(pk, pkoffset, 32, null, 0); // A
            sha512.TransformFinalBlock(m, moffset, mlen); // message
            Array.Copy(sha512.Hash!, hram, 64);
        }

        ScalarOperations.sc_reduce(hram);

        // STEP 4: Verify equation: [s]B = R + [k]A
        // Equivalently: [s]B - [k]A = R
        // Or: [s]B + [k](-A) = R
        byte[] s = new byte[32];
        Array.Copy(sig, sigoffset + 32, s, 0, 32);

        GroupElementP2 R;
        GroupOperations.ge_double_scalarmult_vartime(out R, hram, ref A, s);

        // Encode R and compare with sig[0..31]
        byte[] rcheck = new byte[32];
        GroupOperations.ge_tobytes(rcheck, 0, ref R);

        // Constant-time comparison
        int result = 0;
        for (int i = 0; i < 32; i++)
        {
            result |= rcheck[i] ^ sig[sigoffset + i];
        }

        return result == 0;
    }

    /// <summary>
    /// Checks if a scalar is in the valid range [0, L-1]
    /// where L is the order of the base point.
    /// </summary>
    private static bool sc_isvalid(byte[] s)
    {
        // L = 2^252 + 27742317777372353535851937790883648493
        // Check s < L by comparing bytes from most significant to least

        // L in little-endian bytes
        byte[] L = {
            0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58,
            0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
        };

        // Compare from most significant byte
        for (int i = 31; i >= 0; i--)
        {
            if (s[i] < L[i])
                return true;
            if (s[i] > L[i])
                return false;
        }

        // s == L, which is invalid
        return false;
    }
}
