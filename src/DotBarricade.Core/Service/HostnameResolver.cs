using System.Net;
using System.Net.Sockets;
using DotBarricade.Core.Interface;
using Microsoft.Extensions.Caching.Memory;

namespace DotBarricade.Core.Service;

/// <summary>
/// Reverse-DNS resolver with a small in-process LRU cache.
///
/// It translates a client <see cref="IPAddress"/> into its PTR hostname
/// (e.g. <c>crawl-66-249-66-1.googlebot.com</c>) and caches both positive
/// *and* negative results so the hot path never performs more than one
/// network call per (IP,T-window) tuple.
///
/// <para>
/// **Cache policy**  
/// • Successful look-ups → 30-minute TTL  
/// • Failed → 5-minute TTL  
/// • Max 10 000 entries (≈ 1 MB RAM) – least-recently-used eviction
///   handled by <see cref="MemoryCache"/>.
/// </para>
/// </summary>
public sealed class HostnameResolver : IHostnameResolver
{
    // In-memory cache sized to bound memory use on busy edge nodes.
    private readonly MemoryCache _cache = new(new MemoryCacheOptions { SizeLimit = 10_000 });

    /// <inheritdoc />
    public async ValueTask<string?> ResolveAsync(IPAddress ip, CancellationToken ct = default)
    {
        // ───── 1. Fast path – serve from cache (null is a valid cached value) ─────
        if (_cache.TryGetValue(ip, out string? cached))
            return cached;

        try
        {
            // ───── 2. Reverse-DNS lookup (PTR) ─────
            IPHostEntry entry = await Dns.GetHostEntryAsync(ip.ToString(), ct);
            string host = entry.HostName;

            Cache(ip, host, ttlMinutes: 30);   // positive ttl
            return host;
        }
        catch (SocketException)
        {
            // ───── 3. No PTR record or DNS error – cache null briefly ─────
            Cache(ip, null, ttlMinutes: 5);    // negative ttl
            return null;
        }

        // Local helper keeps the main flow tidy.
        void Cache(IPAddress key, string? value, int ttlMinutes) =>
            _cache.Set(key, value,
                new MemoryCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(ttlMinutes),
                    Size = 1
                });
    }
}
