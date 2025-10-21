namespace HeroSdJwt.Core;

/// <summary>
/// Represents a parsed claim path that can include nested properties and array indices.
/// Examples: "email", "address.street", "degrees[1]", "address.geo.coordinates"
/// </summary>
internal readonly struct ClaimPath
{
    /// <summary>
    /// Gets the base claim name (first component before any dot or array index).
    /// Example: "address" from "address.street" or "degrees" from "degrees[1]"
    /// </summary>
    public string BaseName { get; }

    /// <summary>
    /// Gets the array index if this is an array element reference, otherwise null.
    /// Example: 1 from "degrees[1]"
    /// </summary>
    public int? ArrayIndex { get; }

    /// <summary>
    /// Gets the nested property path after the base name (if any).
    /// Example: "street" from "address.street", or "geo.coordinates" from "address.geo.coordinates"
    /// Null if there's no nesting.
    /// </summary>
    public string? NestedPath { get; }

    /// <summary>
    /// Gets the path components split by dots.
    /// Example: ["address", "street"] for "address.street"
    /// </summary>
    public string[] PathComponents { get; }

    /// <summary>
    /// Gets a value indicating whether this represents an array element.
    /// </summary>
    public bool IsArrayElement => ArrayIndex.HasValue;

    /// <summary>
    /// Gets a value indicating whether this represents a nested property.
    /// </summary>
    public bool IsNested => NestedPath != null;

    /// <summary>
    /// Gets the original claim specification.
    /// </summary>
    public string OriginalSpec { get; }

    private ClaimPath(string originalSpec, string baseName, int? arrayIndex, string? nestedPath, string[] pathComponents)
    {
        OriginalSpec = originalSpec;
        BaseName = baseName;
        ArrayIndex = arrayIndex;
        NestedPath = nestedPath;
        PathComponents = pathComponents;
    }

    /// <summary>
    /// Parses a claim specification into a ClaimPath.
    /// Supports formats:
    /// - Simple: "claimName"
    /// - Nested: "address.street", "address.geo.coordinates"
    /// - Array: "degrees[1]"
    /// Note: Nested properties in arrays (e.g., "education[0].institution") not yet supported.
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
            // No array syntax - check for nested property (dot notation)
            var dotIndex = claimSpec.IndexOf('.');

            if (dotIndex == -1)
            {
                // Simple claim name without array index or nesting
                return new ClaimPath(claimSpec, claimSpec, null, null, new[] { claimSpec });
            }
            else
            {
                // Nested property path
                if (dotIndex == 0)
                {
                    throw new ArgumentException($"Invalid claim specification '{claimSpec}': cannot start with '.'", nameof(claimSpec));
                }

                if (dotIndex == claimSpec.Length - 1)
                {
                    throw new ArgumentException($"Invalid claim specification '{claimSpec}': cannot end with '.'", nameof(claimSpec));
                }

                var pathComponents = claimSpec.Split('.');

                // Validate each component is non-empty
                foreach (var component in pathComponents)
                {
                    if (string.IsNullOrWhiteSpace(component))
                    {
                        throw new ArgumentException($"Invalid claim specification '{claimSpec}': empty path component", nameof(claimSpec));
                    }
                }

                var baseName = pathComponents[0];
                var nestedPath = string.Join(".", pathComponents.Skip(1));

                return new ClaimPath(claimSpec, baseName, null, nestedPath, pathComponents);
            }
        }
        else
        {
            // Array syntax found
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

            // Verify nothing after closing bracket (nested properties in arrays not yet supported)
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

            return new ClaimPath(claimSpec, baseName, index, null, new[] { baseName });
        }
    }

    public override string ToString()
    {
        return OriginalSpec;
    }
}
