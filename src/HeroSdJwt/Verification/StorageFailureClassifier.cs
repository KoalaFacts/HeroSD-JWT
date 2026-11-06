namespace HeroSdJwt.Verification;

/// <summary>
/// A store failure may bypass a configured security check only when it is a
/// recognizable transport outage or timeout. Unknown exceptions may indicate
/// malformed records or incorrect provider implementations.
/// </summary>
internal static class StorageFailureClassifier
{
    internal static bool IsTransient(Exception error) =>
        error is System.IO.IOException or
            TimeoutException or
            System.Net.Http.HttpRequestException or
            System.Net.Sockets.SocketException or
            System.Data.Common.DbException;
}
