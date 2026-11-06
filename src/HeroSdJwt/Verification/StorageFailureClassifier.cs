using System.Data.Common;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;

namespace HeroSdJwt.Verification;

/// <summary>
/// A store failure may bypass a configured security check only when it is a
/// recognizable transport outage or timeout. Unknown exceptions may indicate
/// malformed records or incorrect provider implementations.
/// </summary>
internal static class StorageFailureClassifier
{
    internal static bool IsTransient(Exception error) =>
        error switch
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
