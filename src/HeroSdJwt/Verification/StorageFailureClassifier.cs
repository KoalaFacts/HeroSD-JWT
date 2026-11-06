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
    internal static bool IsTransient(Exception error)
    {
        // Storage libraries can wrap a corrupt record, rejected request or
        // invalid provider state inside a recognizable transport exception.
        // Every cause must be a known temporary failure: classifying only the
        // outermost wrapper could silently bypass replay and revocation checks.
        for (Exception? cause = error; cause is not null; cause = cause.InnerException)
        {
            if (!IsKnownTemporaryFailure(cause))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsKnownTemporaryFailure(Exception cause) =>
        cause switch
        {
            // Provider-reported nontransient errors include schema/constraint faults.
            DbException databaseError => databaseError.IsTransient,
            // .NET 8+ reports specific HTTP failures even without a response
            // status or inner exception. TLS trust, authentication, and
            // malformed responses must not bypass replay or revocation.
            HttpRequestException httpError =>
                (httpError.HttpRequestError is HttpRequestError.Unknown or
                    HttpRequestError.NameResolutionError or HttpRequestError.ConnectionError or
                    HttpRequestError.ResponseEnded) &&
                (httpError.StatusCode is null or HttpStatusCode.RequestTimeout or HttpStatusCode.TooManyRequests ||
                    (int)httpError.StatusCode.Value >= 500),
            // HttpIOException derives from IOException: a malformed or
            // oversized response is not a temporary network interruption.
            HttpIOException httpIoError =>
                httpIoError.HttpRequestError is HttpRequestError.ConnectionError or HttpRequestError.ResponseEnded,
            // These IOException subclasses can reflect corrupt records or
            // broken local configuration rather than temporary transport faults.
            InvalidDataException or EndOfStreamException or FileNotFoundException or
                DirectoryNotFoundException or PathTooLongException => false,
            IOException => true,
            TimeoutException => true,
            SocketException => true,
            // Unknown nested causes (including TLS trust, cancellation,
            // authorization, JSON parsing and invalid provider state) fail closed.
            _ => false
        };
}
