using HeroSdJwt.Exceptions;
using HeroSdJwt.Primitives;
using Xunit;

namespace HeroSdJwt.Tests.Unit.Exceptions;

/// <summary>
/// Tests for SD-JWT exception classes.
/// Validates exception construction, inheritance, and error code handling.
/// </summary>
public class ExceptionTests
{
    #region SdJwtException Tests

    [Fact]
    public void SdJwtException_Constructor_SetsMessageAndErrorCode()
    {
        // Arrange
        var message = "Test error message";
        var errorCode = ErrorCode.InvalidInput;

        // Act
        var exception = new SdJwtException(message, errorCode);

        // Assert
        Assert.Equal(message, exception.Message);
        Assert.Equal(errorCode, exception.ErrorCode);
        Assert.Null(exception.InnerException);
    }

    [Fact]
    public void SdJwtException_ConstructorWithInnerException_SetsAllProperties()
    {
        // Arrange
        var message = "Outer exception";
        var errorCode = ErrorCode.InvalidInput;
        var innerException = new InvalidOperationException("Inner exception");

        // Act
        var exception = new SdJwtException(message, errorCode, innerException);

        // Assert
        Assert.Equal(message, exception.Message);
        Assert.Equal(errorCode, exception.ErrorCode);
        Assert.Same(innerException, exception.InnerException);
    }

    [Fact]
    public void SdJwtException_InheritsFromException()
    {
        // Arrange & Act
        var exception = new SdJwtException("test", ErrorCode.InvalidInput);

        // Assert
        Assert.IsAssignableFrom<Exception>(exception);
    }

    #endregion

    #region SignatureInvalidException Tests

    [Fact]
    public void SignatureInvalidException_Constructor_SetsMessageAndErrorCode()
    {
        // Arrange
        var message = "Signature verification failed";

        // Act
        var exception = new SignatureInvalidException(message);

        // Assert
        Assert.Equal(message, exception.Message);
        Assert.Equal(ErrorCode.InvalidSignature, exception.ErrorCode);
        Assert.Null(exception.InnerException);
    }

    [Fact]
    public void SignatureInvalidException_ConstructorWithInnerException_SetsAllProperties()
    {
        // Arrange
        var message = "Signature verification failed";
        var innerException = new InvalidOperationException("Crypto error");

        // Act
        var exception = new SignatureInvalidException(message, innerException);

        // Assert
        Assert.Equal(message, exception.Message);
        Assert.Equal(ErrorCode.InvalidSignature, exception.ErrorCode);
        Assert.Same(innerException, exception.InnerException);
    }

    [Fact]
    public void SignatureInvalidException_InheritsFromSdJwtException()
    {
        // Arrange & Act
        var exception = new SignatureInvalidException("test");

        // Assert
        Assert.IsAssignableFrom<SdJwtException>(exception);
        Assert.IsAssignableFrom<Exception>(exception);
    }

    [Fact]
    public void SignatureInvalidException_CanBeCaught_AsSdJwtException()
    {
        // Arrange
        var exceptionThrown = false;

        // Act
        try
        {
            throw new SignatureInvalidException("test");
        }
        catch (SdJwtException ex)
        {
            exceptionThrown = true;
            Assert.Equal(ErrorCode.InvalidSignature, ex.ErrorCode);
        }

        // Assert
        Assert.True(exceptionThrown);
    }

    #endregion

    #region DigestMismatchException Tests

    [Fact]
    public void DigestMismatchException_Constructor_SetsMessageAndErrorCode()
    {
        // Arrange
        var message = "Digest does not match";

        // Act
        var exception = new DigestMismatchException(message);

        // Assert
        Assert.Equal(message, exception.Message);
        Assert.Equal(ErrorCode.DigestMismatch, exception.ErrorCode);
        Assert.Null(exception.InnerException);
    }

    [Fact]
    public void DigestMismatchException_InheritsFromSdJwtException()
    {
        // Arrange & Act
        var exception = new DigestMismatchException("test");

        // Assert
        Assert.IsAssignableFrom<SdJwtException>(exception);
        Assert.IsAssignableFrom<Exception>(exception);
    }

    [Fact]
    public void DigestMismatchException_CanBeCaught_AsSdJwtException()
    {
        // Arrange
        var exceptionThrown = false;

        // Act
        try
        {
            throw new DigestMismatchException("test");
        }
        catch (SdJwtException ex)
        {
            exceptionThrown = true;
            Assert.Equal(ErrorCode.DigestMismatch, ex.ErrorCode);
        }

        // Assert
        Assert.True(exceptionThrown);
    }

    #endregion

    #region ClaimExpiredException Tests

    [Fact]
    public void ClaimExpiredException_WithTokenExpiredCode_SetsCorrectErrorCode()
    {
        // Arrange
        var message = "Token has expired";
        var errorCode = ErrorCode.TokenExpired;

        // Act
        var exception = new ClaimExpiredException(message, errorCode);

        // Assert
        Assert.Equal(message, exception.Message);
        Assert.Equal(ErrorCode.TokenExpired, exception.ErrorCode);
        Assert.Null(exception.InnerException);
    }

    [Fact]
    public void ClaimExpiredException_WithTokenNotYetValidCode_SetsCorrectErrorCode()
    {
        // Arrange
        var message = "Token is not yet valid";
        var errorCode = ErrorCode.TokenNotYetValid;

        // Act
        var exception = new ClaimExpiredException(message, errorCode);

        // Assert
        Assert.Equal(message, exception.Message);
        Assert.Equal(ErrorCode.TokenNotYetValid, exception.ErrorCode);
        Assert.Null(exception.InnerException);
    }

    [Fact]
    public void ClaimExpiredException_InheritsFromSdJwtException()
    {
        // Arrange & Act
        var exception = new ClaimExpiredException("test", ErrorCode.TokenExpired);

        // Assert
        Assert.IsAssignableFrom<SdJwtException>(exception);
        Assert.IsAssignableFrom<Exception>(exception);
    }

    [Fact]
    public void ClaimExpiredException_CanBeCaught_AsSdJwtException()
    {
        // Arrange
        var exceptionThrown = false;

        // Act
        try
        {
            throw new ClaimExpiredException("test", ErrorCode.TokenExpired);
        }
        catch (SdJwtException ex)
        {
            exceptionThrown = true;
            Assert.Equal(ErrorCode.TokenExpired, ex.ErrorCode);
        }

        // Assert
        Assert.True(exceptionThrown);
    }

    #endregion

    #region AlgorithmNotSupportedException Tests

    [Fact]
    public void AlgorithmNotSupportedException_Constructor_SetsMessageAndErrorCode()
    {
        // Arrange
        var message = "Algorithm not supported";

        // Act
        var exception = new AlgorithmNotSupportedException(message);

        // Assert
        Assert.Equal(message, exception.Message);
        Assert.Equal(ErrorCode.UnsupportedAlgorithm, exception.ErrorCode);
        Assert.Null(exception.InnerException);
    }

    [Fact]
    public void AlgorithmNotSupportedException_InheritsFromSdJwtException()
    {
        // Arrange & Act
        var exception = new AlgorithmNotSupportedException("test");

        // Assert
        Assert.IsAssignableFrom<SdJwtException>(exception);
        Assert.IsAssignableFrom<Exception>(exception);
    }

    [Fact]
    public void AlgorithmNotSupportedException_CanBeCaught_AsSdJwtException()
    {
        // Arrange
        var exceptionThrown = false;

        // Act
        try
        {
            throw new AlgorithmNotSupportedException("test");
        }
        catch (SdJwtException ex)
        {
            exceptionThrown = true;
            Assert.Equal(ErrorCode.UnsupportedAlgorithm, ex.ErrorCode);
        }

        // Assert
        Assert.True(exceptionThrown);
    }

    #endregion

    #region AlgorithmConfusionException Tests

    [Fact]
    public void AlgorithmConfusionException_Constructor_SetsMessageAndErrorCode()
    {
        // Arrange
        var message = "Algorithm confusion attack detected";

        // Act
        var exception = new AlgorithmConfusionException(message);

        // Assert
        Assert.Equal(message, exception.Message);
        Assert.Equal(ErrorCode.AlgorithmConfusion, exception.ErrorCode);
        Assert.Null(exception.InnerException);
    }

    [Fact]
    public void AlgorithmConfusionException_InheritsFromSdJwtException()
    {
        // Arrange & Act
        var exception = new AlgorithmConfusionException("test");

        // Assert
        Assert.IsAssignableFrom<SdJwtException>(exception);
        Assert.IsAssignableFrom<Exception>(exception);
    }

    [Fact]
    public void AlgorithmConfusionException_CanBeCaught_AsSdJwtException()
    {
        // Arrange
        var exceptionThrown = false;

        // Act
        try
        {
            throw new AlgorithmConfusionException("test");
        }
        catch (SdJwtException ex)
        {
            exceptionThrown = true;
            Assert.Equal(ErrorCode.AlgorithmConfusion, ex.ErrorCode);
        }

        // Assert
        Assert.True(exceptionThrown);
    }

    #endregion

    #region MalformedDisclosureException Tests

    [Fact]
    public void MalformedDisclosureException_Constructor_SetsMessageAndErrorCode()
    {
        // Arrange
        var message = "Disclosure is malformed";

        // Act
        var exception = new MalformedDisclosureException(message);

        // Assert
        Assert.Equal(message, exception.Message);
        Assert.Equal(ErrorCode.MalformedDisclosure, exception.ErrorCode);
        Assert.Null(exception.InnerException);
    }

    [Fact]
    public void MalformedDisclosureException_ConstructorWithInnerException_SetsAllProperties()
    {
        // Arrange
        var message = "Disclosure is malformed";
        var innerException = new InvalidOperationException("Parse error");

        // Act
        var exception = new MalformedDisclosureException(message, innerException);

        // Assert
        Assert.Equal(message, exception.Message);
        Assert.Equal(ErrorCode.MalformedDisclosure, exception.ErrorCode);
        Assert.Same(innerException, exception.InnerException);
    }

    [Fact]
    public void MalformedDisclosureException_InheritsFromSdJwtException()
    {
        // Arrange & Act
        var exception = new MalformedDisclosureException("test");

        // Assert
        Assert.IsAssignableFrom<SdJwtException>(exception);
        Assert.IsAssignableFrom<Exception>(exception);
    }

    [Fact]
    public void MalformedDisclosureException_CanBeCaught_AsSdJwtException()
    {
        // Arrange
        var exceptionThrown = false;

        // Act
        try
        {
            throw new MalformedDisclosureException("test");
        }
        catch (SdJwtException ex)
        {
            exceptionThrown = true;
            Assert.Equal(ErrorCode.MalformedDisclosure, ex.ErrorCode);
        }

        // Assert
        Assert.True(exceptionThrown);
    }

    #endregion

    #region KeyBindingInvalidException Tests

    [Fact]
    public void KeyBindingInvalidException_Constructor_SetsMessageAndErrorCode()
    {
        // Arrange
        var message = "Key binding verification failed";

        // Act
        var exception = new KeyBindingInvalidException(message);

        // Assert
        Assert.Equal(message, exception.Message);
        Assert.Equal(ErrorCode.KeyBindingInvalid, exception.ErrorCode);
        Assert.Null(exception.InnerException);
    }

    [Fact]
    public void KeyBindingInvalidException_ConstructorWithInnerException_SetsAllProperties()
    {
        // Arrange
        var message = "Key binding verification failed";
        var innerException = new InvalidOperationException("Signature error");

        // Act
        var exception = new KeyBindingInvalidException(message, innerException);

        // Assert
        Assert.Equal(message, exception.Message);
        Assert.Equal(ErrorCode.KeyBindingInvalid, exception.ErrorCode);
        Assert.Same(innerException, exception.InnerException);
    }

    [Fact]
    public void KeyBindingInvalidException_InheritsFromSdJwtException()
    {
        // Arrange & Act
        var exception = new KeyBindingInvalidException("test");

        // Assert
        Assert.IsAssignableFrom<SdJwtException>(exception);
        Assert.IsAssignableFrom<Exception>(exception);
    }

    [Fact]
    public void KeyBindingInvalidException_CanBeCaught_AsSdJwtException()
    {
        // Arrange
        var exceptionThrown = false;

        // Act
        try
        {
            throw new KeyBindingInvalidException("test");
        }
        catch (SdJwtException ex)
        {
            exceptionThrown = true;
            Assert.Equal(ErrorCode.KeyBindingInvalid, ex.ErrorCode);
        }

        // Assert
        Assert.True(exceptionThrown);
    }

    #endregion

    #region Exception Hierarchy Tests

    [Fact]
    public void AllCustomExceptions_InheritFromSdJwtException()
    {
        // Arrange & Act & Assert
        Assert.IsAssignableFrom<SdJwtException>(new SignatureInvalidException("test"));
        Assert.IsAssignableFrom<SdJwtException>(new DigestMismatchException("test"));
        Assert.IsAssignableFrom<SdJwtException>(new ClaimExpiredException("test", ErrorCode.TokenExpired));
        Assert.IsAssignableFrom<SdJwtException>(new AlgorithmNotSupportedException("test"));
        Assert.IsAssignableFrom<SdJwtException>(new AlgorithmConfusionException("test"));
        Assert.IsAssignableFrom<SdJwtException>(new MalformedDisclosureException("test"));
        Assert.IsAssignableFrom<SdJwtException>(new KeyBindingInvalidException("test"));
    }

    [Fact]
    public void AllCustomExceptions_HaveUniqueErrorCodes()
    {
        // Arrange
        var exceptions = new[]
        {
            new SignatureInvalidException("test").ErrorCode,
            new DigestMismatchException("test").ErrorCode,
            new ClaimExpiredException("test", ErrorCode.TokenExpired).ErrorCode,
            new ClaimExpiredException("test", ErrorCode.TokenNotYetValid).ErrorCode,
            new AlgorithmNotSupportedException("test").ErrorCode,
            new AlgorithmConfusionException("test").ErrorCode,
            new MalformedDisclosureException("test").ErrorCode,
            new KeyBindingInvalidException("test").ErrorCode
        };

        // Act
        var uniqueErrorCodes = exceptions.Distinct().ToArray();

        // Assert
        Assert.Equal(exceptions.Length, uniqueErrorCodes.Length);
    }

    #endregion
}
