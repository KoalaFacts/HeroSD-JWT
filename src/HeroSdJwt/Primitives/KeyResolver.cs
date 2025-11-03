namespace HeroSdJwt.Primitives;

/// <summary>
/// Resolves key identifiers to verification keys.
/// Applications provide implementations to map key IDs to public keys or shared secrets.
/// </summary>
/// <param name="keyId">The key identifier from the JWT header.</param>
/// <returns>
/// The verification key (byte array) for the specified key ID,
/// or null if the key ID is not recognized.
/// </returns>
/// <remarks>
/// <para>
/// This delegate enables key rotation by allowing verifiers to dynamically select
/// verification keys based on the 'kid' (key ID) parameter in the JWT header.
/// </para>
/// <para>
/// <b>Implementation Guidelines:</b>
/// </para>
/// <list type="bullet">
/// <item><description><b>Return null for unknown keys</b> - Do not throw exceptions for unknown key IDs. Return null to indicate the key was not found.</description></item>
/// <item><description><b>Handle exceptions safely</b> - The library will catch and log exceptions from resolver implementations.</description></item>
/// <item><description><b>Use caching</b> - Key resolution may be called multiple times. Consider caching keys for performance.</description></item>
/// <item><description><b>Thread safety</b> - The resolver may be called from multiple threads concurrently. Ensure thread-safe implementations.</description></item>
/// <item><description><b>Fast lookups</b> - Resolution is on the critical path of signature verification. Keep lookups fast (target: &lt;100ms).</description></item>
/// </list>
/// <para>
/// <b>Example Implementation (In-Memory Dictionary):</b>
/// </para>
/// <code>
/// var keys = new Dictionary&lt;string, byte[]&gt;
/// {
///     ["key-v1"] = oldPublicKey,
///     ["key-v2"] = newPublicKey
/// };
/// KeyResolver resolver = keyId => keys.GetValueOrDefault(keyId);
/// </code>
/// <para>
/// <b>Example Implementation (Database with Caching):</b>
/// </para>
/// <code>
/// public class DatabaseKeyResolver
/// {
///     private readonly IKeyRepository repository;
///     private readonly IMemoryCache cache;
///
///     public byte[]? Resolve(string keyId)
///     {
///         if (cache.TryGetValue(keyId, out byte[] cached))
///             return cached;
///
///         var key = repository.GetKeyById(keyId);
///         if (key != null)
///             cache.Set(keyId, key, TimeSpan.FromHours(1));
///
///         return key;
///     }
/// }
/// KeyResolver resolver = dbResolver.Resolve;
/// </code>
/// </remarks>
public delegate byte[]? KeyResolver(string keyId);
