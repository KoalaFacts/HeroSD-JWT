using System.Buffers.Text;
using System.Security.Cryptography;
using Constants = HeroSdJwt.Primitives.Constants;
using HashAlgorithm = HeroSdJwt.Primitives.HashAlgorithm;

namespace HeroSdJwt.Issuance;

/// <summary>
/// Calculates cryptographic digests of disclosure documents.
/// Digest = Base64url(Hash(disclosure))
/// </summary>
public class DigestCalculator : IDigestCalculator
{
    // Disclosure hashing must not silently turn malformed UTF-16 into the
    // replacement character: two different caller inputs could then hash alike.
    private static readonly System.Text.UTF8Encoding _strictUtf8 = new(false, true);

    /// <summary>
    /// Computes the digest of a disclosure using the specified hash algorithm.
    /// </summary>
    /// <param name="disclosure">The base64url-encoded disclosure.</param>
    /// <param name="algorithm">The hash algorithm to use.</param>
    /// <returns>The base64url-encoded digest.</returns>
    public string ComputeDigest(string disclosure, HashAlgorithm algorithm)
    {
        ArgumentNullException.ThrowIfNull(disclosure);

        // Direct callers can supply far more text than a verifier accepts on
        // the wire. Bound UTF-8 size before allocating its proportional buffer.
        // Each UTF-16 code unit needs at most three UTF-8 bytes, so ordinary
        // short disclosures avoid an extra GetByteCount scan.
        if (disclosure.Length > Constants.MAX_JWT_SIZE_BYTES ||
            (disclosure.Length > Constants.MAX_JWT_SIZE_BYTES / 3 &&
             GetStrictUtf8ByteCount(disclosure) > Constants.MAX_JWT_SIZE_BYTES))
        {
            throw new ArgumentException(
                $"Disclosure exceeds the maximum of {Constants.MAX_JWT_SIZE_BYTES} UTF-8 bytes.",
                nameof(disclosure));
        }

        if (string.IsNullOrWhiteSpace(disclosure))
        {
            throw new ArgumentException("Disclosure cannot be empty or whitespace.", nameof(disclosure));
        }

        // Typical base64url disclosures are short. Avoid a new UTF-8 byte[] for
        // every digest while preserving UTF-8 semantics for direct Unicode callers.
        // Up to three UTF-8 bytes per UTF-16 code unit fits this bounded buffer.
        const int StackDisclosureLimit = 256;
        Span<byte> disclosureScratch = stackalloc byte[StackDisclosureLimit * 3];
        ReadOnlySpan<byte> disclosureBytes = disclosure.Length <= StackDisclosureLimit
            ? disclosureScratch[..GetStrictUtf8Bytes(disclosure.AsSpan(), disclosureScratch)]
            : GetStrictUtf8Bytes(disclosure);

        // Hash directly into a fixed stack buffer. Every disclosure digest is
        // computed during issuance and verification; avoid a heap byte[] per
        // SHA-256/384/512 result without changing the encoded digest.
        Span<byte> hashBytes = stackalloc byte[64];
        int hashLength = algorithm switch
        {
            HashAlgorithm.Sha256 => SHA256.HashData(disclosureBytes, hashBytes),
            HashAlgorithm.Sha384 => SHA384.HashData(disclosureBytes, hashBytes),
            HashAlgorithm.Sha512 => SHA512.HashData(disclosureBytes, hashBytes),
            _ => throw new ArgumentException($"Unsupported hash algorithm: {algorithm}", nameof(algorithm))
        };

        return Base64Url.EncodeToString(hashBytes[..hashLength]);
    }

    private static int GetStrictUtf8Bytes(ReadOnlySpan<char> disclosure, Span<byte> destination)
    {
        try
        {
            return _strictUtf8.GetBytes(disclosure, destination);
        }
        catch (System.Text.EncoderFallbackException ex)
        {
            throw new ArgumentException("Disclosure contains invalid UTF-16 text.", nameof(disclosure), ex);
        }
    }

    private static byte[] GetStrictUtf8Bytes(string disclosure)
    {
        try
        {
            return _strictUtf8.GetBytes(disclosure);
        }
        catch (System.Text.EncoderFallbackException ex)
        {
            throw new ArgumentException("Disclosure contains invalid UTF-16 text.", nameof(disclosure), ex);
        }
    }

    private static int GetStrictUtf8ByteCount(string disclosure)
    {
        try
        {
            return _strictUtf8.GetByteCount(disclosure);
        }
        catch (System.Text.EncoderFallbackException ex)
        {
            throw new ArgumentException("Disclosure contains invalid UTF-16 text.", nameof(disclosure), ex);
        }
    }
}
