using System.Data.Common;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security;
using System.Security.Authentication;
using System.Security.Cryptography;

namespace HeroSdJwt.Verification;

/// <summary>
/// A store failure may bypass a configured security check only when it is a
/// recognizable transport outage or timeout. Unknown exceptions may indicate
/// malformed records or incorrect provider implementations.
/// </summary>
internal static class StorageFailureClassifier
{
    internal static bool IsTransient(Exception error)
    {
        // HTTP clients and storage providers can wrap permanent TLS trust,
        // authorization or decryption failures inside IOException or
        // HttpRequestException. These must never bypass replay/revocation.
        for (Exception? cause = error; cause is not null; cause = cause.InnerException)
        {
            if (cause is AuthenticationException or UnauthorizedAccessException or
                SecurityException or CryptographicException)
            {
                return false;
            }
        }

        return error switch
        {
            // DbException also covers schema and constraint errors, which
            // cannot safely bypass revocation or replay protection.
            DbException databaseError => databaseError.IsTransient,
            // Authentication/configuration mistakes (e.g. HTTP 401/403/404)
            // require intervention. Allow only timeout, throttling or 5xx.
            HttpRequestException httpError =>
                httpError.StatusCode is null or HttpStatusCode.RequestTimeout or HttpStatusCode.TooManyRequests ||
                (int)httpError.StatusCode.Value >= 500,
            IOException => true,
            TimeoutException => true,
            SocketException => true,
            _ => false
        };
    }
}
