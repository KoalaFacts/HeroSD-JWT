using System.Collections.ObjectModel;
using System.Text.Json;
using ErrorCode = HeroSdJwt.Primitives.ErrorCode;

namespace HeroSdJwt.Models;

/// <summary>
/// Represents the result of an SD-JWT verification operation.
/// Contains validation status, disclosed claims, and any errors encountered.
/// </summary>
public sealed class VerificationResult
{
    /// <summary>
    /// Gets a value indicating whether the verification succeeded.
    /// </summary>
    public bool IsValid { get; }

    /// <summary>
    /// Gets the list of error codes encountered during verification.
    /// Empty if IsValid is true.
    /// </summary>
    public IReadOnlyList<ErrorCode> Errors { get; }

    /// <summary>
    /// Gets the disclosed claims from the verified SD-JWT.
    /// Only populated if IsValid is true.
    /// </summary>
    public IReadOnlyDictionary<string, JsonElement> DisclosedClaims { get; }

    /// <summary>
    /// Gets additional error details for debugging.
    /// Only populated when errors occur.
    /// </summary>
    public string? ErrorDetails { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="VerificationResult"/> class for a successful verification.
    /// </summary>
    /// <param name="disclosedClaims">The disclosed claims.</param>
    public VerificationResult(IReadOnlyDictionary<string, JsonElement> disclosedClaims)
    {
        ArgumentNullException.ThrowIfNull(disclosedClaims);

        IsValid = true;
        Errors = Array.Empty<ErrorCode>();
        DisclosedClaims = disclosedClaims;
        ErrorDetails = null;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="VerificationResult"/> class for a failed verification.
    /// </summary>
    /// <param name="errors">The list of error codes.</param>
    /// <param name="errorDetails">Optional error details.</param>
    public VerificationResult(IEnumerable<ErrorCode> errors, string? errorDetails = null)
    {
        ArgumentNullException.ThrowIfNull(errors);

        var errorList = errors.ToList();
        if (errorList.Count == 0)
        {
            throw new ArgumentException("At least one error code must be provided for failed verification.", nameof(errors));
        }

        IsValid = false;
        Errors = new ReadOnlyCollection<ErrorCode>(errorList);
        DisclosedClaims = new ReadOnlyDictionary<string, JsonElement>(new Dictionary<string, JsonElement>());
        ErrorDetails = errorDetails;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="VerificationResult"/> class for a failed verification with a single error.
    /// </summary>
    /// <param name="error">The error code.</param>
    /// <param name="errorDetails">Optional error details.</param>
    public VerificationResult(ErrorCode error, string? errorDetails = null)
        : this(new[] { error }, errorDetails)
    {
    }

    /// <summary>
    /// Returns a string representation of this verification result.
    /// </summary>
    public override string ToString()
    {
        if (IsValid)
        {
            return $"VerificationResult(Valid, Claims={DisclosedClaims.Count})";
        }

        return $"VerificationResult(Invalid, Errors=[{string.Join(", ", Errors)}])";
    }
}
