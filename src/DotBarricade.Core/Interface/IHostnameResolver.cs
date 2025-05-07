using System.Net;

namespace DotBarricade.Core.Interface;

/// <summary>
/// Contract for resolving a client <see cref="IPAddress"/> to its canonical
/// DNS hostname (PTR record).
///
/// Implementations are expected to:
/// <list type="bullet">
///   <item>Perform non-blocking, asynchronous look-ups.</item>
///   <item>Cache results aggressively to keep the hot path allocation-free.</item>
///   <item>Return <c>null</c> when the address has no PTR record or the
///         look-up fails.</item>
/// </list>
/// </summary>
public interface IHostnameResolver
{
    /// <summary>
    /// Asynchronously resolves the supplied IP address to a hostname.
    /// </summary>
    /// <param name="ip">
    /// The IPv4 or IPv6 address to reverse-lookup.
    /// </param>
    /// <param name="ct">
    /// Propagates notification that the caller wishes to cancel the operation.
    /// </param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> whose <c>Result</c> is the resolved
    /// hostname, or <c>null</c> if no PTR record exists.
    /// </returns>
    ValueTask<string?> ResolveAsync(IPAddress ip, CancellationToken ct = default);
}