namespace HeroSdJwt.Core;

/// <summary>
/// Represents a parsed claim path that can include array indices.
/// Examples: "email", "address.street", "degrees[1]", "education[0].institution"
/// </summary>
internal readonly struct ClaimPath
{
    /// <summary>
    /// Gets the base claim name (before any array index or nested property).
    /// Example: "degrees" from "degrees[1]" or "education" from "education[0].institution"
    /// </summary>
    public string BaseName { get; }

    /// <summary>
    /// Gets the array index if this is an array element reference, otherwise null.
    /// Example: 1 from "degrees[1]"
    /// </summary>
    public int? ArrayIndex { get; }

    /// <summary>
    /// Gets a value indicating whether this represents an array element.
    /// </summary>
    public bool IsArrayElement => ArrayIndex.HasValue;

    /// <summary>
    /// Gets the original claim specification.
    /// </summary>
    public string OriginalSpec { get; }

    private ClaimPath(string originalSpec, string baseName, int? arrayIndex)
    {
        OriginalSpec = originalSpec;
        BaseName = baseName;
        ArrayIndex = arrayIndex;
    }

    /// <summary>
    /// Parses a claim specification into a ClaimPath.
    /// Supports formats: "claimName", "claimName[index]"
    /// </summary>
    /// <param name="claimSpec">The claim specification string.</param>
    /// <returns>Parsed ClaimPath.</returns>
    /// <exception cref="ArgumentException">Thrown when the format is invalid.</exception>
    public static ClaimPath Parse(string claimSpec)
    {
        ArgumentNullException.ThrowIfNull(claimSpec);

        if (string.IsNullOrWhiteSpace(claimSpec))
        {
            throw new ArgumentException("Claim specification cannot be empty or whitespace.", nameof(claimSpec));
        }

        // Check for array syntax: claimName[index]
        var openBracket = claimSpec.IndexOf('[');
        if (openBracket == -1)
        {
            // Simple claim name without array index
            return new ClaimPath(claimSpec, claimSpec, null);
        }

        // Extract base name (before '[')
        if (openBracket == 0)
        {
            throw new ArgumentException($"Invalid claim specification '{claimSpec}': must have a claim name before '['", nameof(claimSpec));
        }

        var baseName = claimSpec.Substring(0, openBracket);

        // Find closing bracket
        var closeBracket = claimSpec.IndexOf(']', openBracket);
        if (closeBracket == -1)
        {
            throw new ArgumentException($"Invalid claim specification '{claimSpec}': missing closing ']'", nameof(claimSpec));
        }

        // Verify nothing after closing bracket (nested properties not yet supported)
        if (closeBracket != claimSpec.Length - 1)
        {
            throw new ArgumentException(
                $"Invalid claim specification '{claimSpec}': nested properties in arrays are not yet supported. " +
                "Use simple array element syntax like 'degrees[1]'",
                nameof(claimSpec));
        }

        // Extract and parse index
        var indexStr = claimSpec.Substring(openBracket + 1, closeBracket - openBracket - 1);
        if (string.IsNullOrWhiteSpace(indexStr))
        {
            throw new ArgumentException($"Invalid claim specification '{claimSpec}': array index cannot be empty", nameof(claimSpec));
        }

        if (!int.TryParse(indexStr, out var index))
        {
            throw new ArgumentException($"Invalid claim specification '{claimSpec}': array index must be a valid integer", nameof(claimSpec));
        }

        if (index < 0)
        {
            throw new ArgumentException($"Invalid claim specification '{claimSpec}': array index cannot be negative", nameof(claimSpec));
        }

        return new ClaimPath(claimSpec, baseName, index);
    }

    public override string ToString()
    {
        return OriginalSpec;
    }
}
