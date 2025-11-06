using HeroSdJwt.Models;
using HeroSdJwt.Primitives;
using System.Text.Json;
using Xunit;

namespace HeroSdJwt.Tests.Unit.Models;

/// <summary>
/// Tests for the VerificationResult model.
/// Validates success and failure scenarios, error handling, and properties.
/// </summary>
public class VerificationResultTests
{
    #region Success Constructor Tests

    [Fact]
    public void Constructor_WithValidClaims_CreatesSuccessResult()
    {
        // Arrange
        var claims = new Dictionary<string, JsonElement>
        {
            ["sub"] = JsonDocument.Parse("\"user123\"").RootElement,
            ["name"] = JsonDocument.Parse("\"John Doe\"").RootElement
        };

        // Act
        var result = new VerificationResult(claims);

        // Assert
        Assert.True(result.IsValid);
        Assert.Empty(result.Errors);
        Assert.Equal(2, result.DisclosedClaims.Count);
        Assert.Null(result.ErrorDetails);
    }

    [Fact]
    public void Constructor_WithEmptyClaims_CreatesSuccessResult()
    {
        // Arrange
        var claims = new Dictionary<string, JsonElement>();

        // Act
        var result = new VerificationResult(claims);

        // Assert
        Assert.True(result.IsValid);
        Assert.Empty(result.Errors);
        Assert.Empty(result.DisclosedClaims);
        Assert.Null(result.ErrorDetails);
    }

    [Fact]
    public void Constructor_WithNullClaims_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            new VerificationResult((IReadOnlyDictionary<string, JsonElement>)null!));
    }

    [Fact]
    public void Constructor_WithClaims_CreatesReadOnlyDictionary()
    {
        // Arrange
        var claims = new Dictionary<string, JsonElement>
        {
            ["test"] = JsonDocument.Parse("\"value\"").RootElement
        };

        // Act
        var result = new VerificationResult(claims);

        // Assert
        Assert.IsAssignableFrom<IReadOnlyDictionary<string, JsonElement>>(result.DisclosedClaims);
    }

    #endregion

    #region Failure Constructor Tests (Multiple Errors)

    [Fact]
    public void Constructor_WithMultipleErrors_CreatesFailureResult()
    {
        // Arrange
        var errors = new[] { ErrorCode.InvalidSignature, ErrorCode.DigestMismatch };
        var errorDetails = "Verification failed";

        // Act
        var result = new VerificationResult(errors, errorDetails);

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal(2, result.Errors.Count);
        Assert.Contains(ErrorCode.InvalidSignature, result.Errors);
        Assert.Contains(ErrorCode.DigestMismatch, result.Errors);
        Assert.Empty(result.DisclosedClaims);
        Assert.Equal("Verification failed", result.ErrorDetails);
    }

    [Fact]
    public void Constructor_WithSingleErrorInList_CreatesFailureResult()
    {
        // Arrange
        var errors = new[] { ErrorCode.InvalidSignature };

        // Act
        var result = new VerificationResult(errors);

        // Assert
        Assert.False(result.IsValid);
        Assert.Single(result.Errors);
        Assert.Equal(ErrorCode.InvalidSignature, result.Errors[0]);
        Assert.Null(result.ErrorDetails);
    }

    [Fact]
    public void Constructor_WithEmptyErrorList_ThrowsArgumentException()
    {
        // Arrange
        var errors = Array.Empty<ErrorCode>();

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            new VerificationResult(errors, "details"));
        Assert.Contains("At least one error code must be provided", exception.Message);
    }

    [Fact]
    public void Constructor_WithNullErrorList_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            new VerificationResult((IEnumerable<ErrorCode>)null!, "details"));
    }

    [Fact]
    public void Constructor_WithErrorsWithoutDetails_CreatesResultWithNullDetails()
    {
        // Arrange
        var errors = new[] { ErrorCode.InvalidSignature };

        // Act
        var result = new VerificationResult(errors);

        // Assert
        Assert.False(result.IsValid);
        Assert.Null(result.ErrorDetails);
    }

    [Fact]
    public void Constructor_WithManyErrors_StoresAllErrors()
    {
        // Arrange
        var errors = new[]
        {
            ErrorCode.InvalidSignature,
            ErrorCode.DigestMismatch,
            ErrorCode.TokenExpired,
            ErrorCode.KeyBindingInvalid
        };

        // Act
        var result = new VerificationResult(errors, "Multiple errors");

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal(4, result.Errors.Count);
        Assert.Equal("Multiple errors", result.ErrorDetails);
    }

    #endregion

    #region Failure Constructor Tests (Single Error)

    [Fact]
    public void Constructor_WithSingleError_CreatesFailureResult()
    {
        // Arrange
        var error = ErrorCode.InvalidSignature;
        var errorDetails = "Signature verification failed";

        // Act
        var result = new VerificationResult(error, errorDetails);

        // Assert
        Assert.False(result.IsValid);
        Assert.Single(result.Errors);
        Assert.Equal(ErrorCode.InvalidSignature, result.Errors[0]);
        Assert.Equal("Signature verification failed", result.ErrorDetails);
        Assert.Empty(result.DisclosedClaims);
    }

    [Fact]
    public void Constructor_WithSingleErrorWithoutDetails_CreatesResult()
    {
        // Arrange
        var error = ErrorCode.DigestMismatch;

        // Act
        var result = new VerificationResult(error);

        // Assert
        Assert.False(result.IsValid);
        Assert.Single(result.Errors);
        Assert.Equal(ErrorCode.DigestMismatch, result.Errors[0]);
        Assert.Null(result.ErrorDetails);
    }

    [Fact]
    public void Constructor_WithAllErrorCodes_CreatesResults()
    {
        // Test each error code individually
        var errorCodes = new[]
        {
            ErrorCode.InvalidSignature,
            ErrorCode.DigestMismatch,
            ErrorCode.TokenExpired,
            ErrorCode.KeyBindingInvalid,
            ErrorCode.UnsupportedAlgorithm,
            ErrorCode.AlgorithmConfusion,
            ErrorCode.MalformedDisclosure
        };

        foreach (var errorCode in errorCodes)
        {
            // Act
            var result = new VerificationResult(errorCode, $"Error: {errorCode}");

            // Assert
            Assert.False(result.IsValid);
            Assert.Single(result.Errors);
            Assert.Equal(errorCode, result.Errors[0]);
            Assert.Equal($"Error: {errorCode}", result.ErrorDetails);
        }
    }

    #endregion

    #region Properties Tests

    [Fact]
    public void IsValid_OnSuccessResult_ReturnsTrue()
    {
        // Arrange
        var claims = new Dictionary<string, JsonElement>
        {
            ["test"] = JsonDocument.Parse("\"value\"").RootElement
        };

        // Act
        var result = new VerificationResult(claims);

        // Assert
        Assert.True(result.IsValid);
    }

    [Fact]
    public void IsValid_OnFailureResult_ReturnsFalse()
    {
        // Arrange
        var result = new VerificationResult(ErrorCode.InvalidSignature);

        // Assert
        Assert.False(result.IsValid);
    }

    [Fact]
    public void Errors_OnSuccessResult_IsEmpty()
    {
        // Arrange
        var claims = new Dictionary<string, JsonElement>();
        var result = new VerificationResult(claims);

        // Assert
        Assert.Empty(result.Errors);
    }

    [Fact]
    public void Errors_OnFailureResult_ContainsErrors()
    {
        // Arrange
        var result = new VerificationResult(ErrorCode.InvalidSignature);

        // Assert
        Assert.NotEmpty(result.Errors);
    }

    [Fact]
    public void DisclosedClaims_OnSuccessResult_ContainsClaims()
    {
        // Arrange
        var claims = new Dictionary<string, JsonElement>
        {
            ["claim1"] = JsonDocument.Parse("\"value1\"").RootElement,
            ["claim2"] = JsonDocument.Parse("123").RootElement
        };

        // Act
        var result = new VerificationResult(claims);

        // Assert
        Assert.Equal(2, result.DisclosedClaims.Count);
        Assert.True(result.DisclosedClaims.ContainsKey("claim1"));
        Assert.True(result.DisclosedClaims.ContainsKey("claim2"));
    }

    [Fact]
    public void DisclosedClaims_OnFailureResult_IsEmpty()
    {
        // Arrange
        var result = new VerificationResult(ErrorCode.InvalidSignature);

        // Assert
        Assert.Empty(result.DisclosedClaims);
    }

    [Fact]
    public void ErrorDetails_OnSuccessResult_IsNull()
    {
        // Arrange
        var claims = new Dictionary<string, JsonElement>();
        var result = new VerificationResult(claims);

        // Assert
        Assert.Null(result.ErrorDetails);
    }

    [Fact]
    public void ErrorDetails_OnFailureResultWithDetails_ReturnsDetails()
    {
        // Arrange
        var result = new VerificationResult(ErrorCode.InvalidSignature, "Details here");

        // Assert
        Assert.Equal("Details here", result.ErrorDetails);
    }

    #endregion

    #region ToString Tests

    [Fact]
    public void ToString_OnSuccessResult_ShowsValidAndClaimCount()
    {
        // Arrange
        var claims = new Dictionary<string, JsonElement>
        {
            ["claim1"] = JsonDocument.Parse("\"value1\"").RootElement,
            ["claim2"] = JsonDocument.Parse("\"value2\"").RootElement
        };
        var result = new VerificationResult(claims);

        // Act
        var str = result.ToString();

        // Assert
        Assert.Contains("Valid", str);
        Assert.Contains("Claims=2", str);
    }

    [Fact]
    public void ToString_OnSuccessResultWithNoClaims_ShowsZeroCount()
    {
        // Arrange
        var claims = new Dictionary<string, JsonElement>();
        var result = new VerificationResult(claims);

        // Act
        var str = result.ToString();

        // Assert
        Assert.Contains("Valid", str);
        Assert.Contains("Claims=0", str);
    }

    [Fact]
    public void ToString_OnFailureResultWithSingleError_ShowsInvalidAndError()
    {
        // Arrange
        var result = new VerificationResult(ErrorCode.InvalidSignature);

        // Act
        var str = result.ToString();

        // Assert
        Assert.Contains("Invalid", str);
        Assert.Contains("InvalidSignature", str);
    }

    [Fact]
    public void ToString_OnFailureResultWithMultipleErrors_ShowsAllErrors()
    {
        // Arrange
        var errors = new[] { ErrorCode.InvalidSignature, ErrorCode.DigestMismatch };
        var result = new VerificationResult(errors);

        // Act
        var str = result.ToString();

        // Assert
        Assert.Contains("Invalid", str);
        Assert.Contains("InvalidSignature", str);
        Assert.Contains("DigestMismatch", str);
    }

    #endregion

    #region Edge Case Tests

    [Fact]
    public void Constructor_WithLargeNumberOfClaims_HandlesCorrectly()
    {
        // Arrange
        var claims = new Dictionary<string, JsonElement>();
        for (int i = 0; i < 100; i++)
        {
            claims[$"claim{i}"] = JsonDocument.Parse($"\"{i}\"").RootElement;
        }

        // Act
        var result = new VerificationResult(claims);

        // Assert
        Assert.True(result.IsValid);
        Assert.Equal(100, result.DisclosedClaims.Count);
    }

    [Fact]
    public void Constructor_WithComplexJsonClaims_StoresCorrectly()
    {
        // Arrange
        var claims = new Dictionary<string, JsonElement>
        {
            ["simple"] = JsonDocument.Parse("\"string\"").RootElement,
            ["number"] = JsonDocument.Parse("42").RootElement,
            ["boolean"] = JsonDocument.Parse("true").RootElement,
            ["null"] = JsonDocument.Parse("null").RootElement,
            ["object"] = JsonDocument.Parse("{\"nested\": \"value\"}").RootElement,
            ["array"] = JsonDocument.Parse("[1, 2, 3]").RootElement
        };

        // Act
        var result = new VerificationResult(claims);

        // Assert
        Assert.True(result.IsValid);
        Assert.Equal(6, result.DisclosedClaims.Count);
        Assert.Equal(JsonValueKind.String, result.DisclosedClaims["simple"].ValueKind);
        Assert.Equal(JsonValueKind.Number, result.DisclosedClaims["number"].ValueKind);
        Assert.Equal(JsonValueKind.True, result.DisclosedClaims["boolean"].ValueKind);
        Assert.Equal(JsonValueKind.Null, result.DisclosedClaims["null"].ValueKind);
        Assert.Equal(JsonValueKind.Object, result.DisclosedClaims["object"].ValueKind);
        Assert.Equal(JsonValueKind.Array, result.DisclosedClaims["array"].ValueKind);
    }

    [Fact]
    public void Constructor_WithLongErrorDetails_StoresCorrectly()
    {
        // Arrange
        var longDetails = new string('a', 10000);
        var result = new VerificationResult(ErrorCode.InvalidSignature, longDetails);

        // Assert
        Assert.Equal(10000, result.ErrorDetails!.Length);
    }

    [Fact]
    public void Constructor_WithEmptyStringErrorDetails_StoresEmptyString()
    {
        // Arrange
        var result = new VerificationResult(ErrorCode.InvalidSignature, string.Empty);

        // Assert
        Assert.Equal(string.Empty, result.ErrorDetails);
    }

    [Fact]
    public void DisclosedClaims_IsReadOnlyDictionary()
    {
        // Arrange
        var claims = new Dictionary<string, JsonElement>
        {
            ["test"] = JsonDocument.Parse("\"value\"").RootElement
        };
        var result = new VerificationResult(claims);

        // Act & Assert
        Assert.IsAssignableFrom<IReadOnlyDictionary<string, JsonElement>>(result.DisclosedClaims);
    }

    [Fact]
    public void Errors_IsReadOnly()
    {
        // Arrange
        var result = new VerificationResult(ErrorCode.InvalidSignature);

        // Act & Assert
        Assert.IsAssignableFrom<IReadOnlyList<ErrorCode>>(result.Errors);
        // Verify we cannot cast to modifiable list
        Assert.False(result.Errors is List<ErrorCode>);
    }

    [Fact]
    public void Constructor_WithClaimsContainingSpecialKeys_StoresCorrectly()
    {
        // Arrange
        var claims = new Dictionary<string, JsonElement>
        {
            ["key-with-dash"] = JsonDocument.Parse("\"value1\"").RootElement,
            ["key_with_underscore"] = JsonDocument.Parse("\"value2\"").RootElement,
            ["key.with.dots"] = JsonDocument.Parse("\"value3\"").RootElement,
            ["key/with/slashes"] = JsonDocument.Parse("\"value4\"").RootElement
        };

        // Act
        var result = new VerificationResult(claims);

        // Assert
        Assert.Equal(4, result.DisclosedClaims.Count);
        Assert.True(result.DisclosedClaims.ContainsKey("key-with-dash"));
        Assert.True(result.DisclosedClaims.ContainsKey("key_with_underscore"));
        Assert.True(result.DisclosedClaims.ContainsKey("key.with.dots"));
        Assert.True(result.DisclosedClaims.ContainsKey("key/with/slashes"));
    }

    #endregion

    #region Collection Isolation Tests

    [Fact]
    public void Constructor_WithErrorList_DoesNotModifyOriginalList()
    {
        // Arrange
        var originalErrors = new List<ErrorCode> { ErrorCode.InvalidSignature };
        var result = new VerificationResult(originalErrors);

        // Act - Modify original
        originalErrors.Add(ErrorCode.DigestMismatch);

        // Assert - Result should still have only one error
        Assert.Single(result.Errors);
        Assert.Equal(ErrorCode.InvalidSignature, result.Errors[0]);
    }

    #endregion
}
