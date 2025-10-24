using HeroSdJwt.Primitives;

namespace HeroSdJwt.Exceptions;

/// <summary>
/// Base exception type for all SD-JWT library errors.
/// </summary>
public class SdJwtException : Exception
{
    /// <summary>
    /// Gets the error code associated with this exception.
    /// </summary>
    public ErrorCode ErrorCode { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="SdJwtException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="errorCode">The error code.</param>
    public SdJwtException(string message, ErrorCode errorCode)
        : base(message)
    {
        ErrorCode = errorCode;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SdJwtException"/> class with an inner exception.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="errorCode">The error code.</param>
    /// <param name="innerException">The inner exception.</param>
    public SdJwtException(string message, ErrorCode errorCode, Exception innerException)
        : base(message, innerException)
    {
        ErrorCode = errorCode;
    }
}

/// <summary>
/// Exception thrown when JWT signature verification fails.
/// </summary>
public class SignatureInvalidException : SdJwtException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="SignatureInvalidException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    public SignatureInvalidException(string message)
        : base(message, ErrorCode.InvalidSignature)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SignatureInvalidException"/> class with an inner exception.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The inner exception.</param>
    public SignatureInvalidException(string message, Exception innerException)
        : base(message, ErrorCode.InvalidSignature, innerException)
    {
    }
}

/// <summary>
/// Exception thrown when a disclosure digest verification fails.
/// </summary>
public class DigestMismatchException : SdJwtException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="DigestMismatchException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    public DigestMismatchException(string message)
        : base(message, ErrorCode.DigestMismatch)
    {
    }
}

/// <summary>
/// Exception thrown when a token has expired.
/// </summary>
public class ClaimExpiredException : SdJwtException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ClaimExpiredException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="errorCode">The specific expiration error code (TokenExpired or TokenNotYetValid).</param>
    public ClaimExpiredException(string message, ErrorCode errorCode)
        : base(message, errorCode)
    {
    }
}

/// <summary>
/// Exception thrown when an unsupported or invalid algorithm is encountered.
/// </summary>
public class AlgorithmNotSupportedException : SdJwtException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AlgorithmNotSupportedException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    public AlgorithmNotSupportedException(string message)
        : base(message, ErrorCode.UnsupportedAlgorithm)
    {
    }
}

/// <summary>
/// Exception thrown when algorithm confusion attack is detected (algorithm is "none").
/// </summary>
public class AlgorithmConfusionException : SdJwtException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AlgorithmConfusionException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    public AlgorithmConfusionException(string message)
        : base(message, ErrorCode.AlgorithmConfusion)
    {
    }
}

/// <summary>
/// Exception thrown when a disclosure document is malformed.
/// </summary>
public class MalformedDisclosureException : SdJwtException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="MalformedDisclosureException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    public MalformedDisclosureException(string message)
        : base(message, ErrorCode.MalformedDisclosure)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="MalformedDisclosureException"/> class with an inner exception.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The inner exception.</param>
    public MalformedDisclosureException(string message, Exception innerException)
        : base(message, ErrorCode.MalformedDisclosure, innerException)
    {
    }
}

/// <summary>
/// Exception thrown when key binding JWT verification fails.
/// </summary>
public class KeyBindingInvalidException : SdJwtException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="KeyBindingInvalidException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    public KeyBindingInvalidException(string message)
        : base(message, ErrorCode.KeyBindingInvalid)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="KeyBindingInvalidException"/> class with an inner exception.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The inner exception.</param>
    public KeyBindingInvalidException(string message, Exception innerException)
        : base(message, ErrorCode.KeyBindingInvalid, innerException)
    {
    }
}
