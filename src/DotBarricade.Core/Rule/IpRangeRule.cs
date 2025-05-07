using System.Net;
using System.Net.Sockets;
using System.Numerics;
using DotBarricade.Core.Interface;
using DotBarricade.Core.Model;
using DotBarricade.Core.Model.Enum;

namespace DotBarricade.Core.Rule;

public sealed class IpRangeRule : IRule
{
    private readonly List<IpRange> _ipv4Ranges;
    private readonly List<IpRange> _ipv6Ranges;

    private readonly struct IpRange
    {
        public readonly object Start;
        public readonly object End;
        public IpRange(object start, object end) => (Start, End) = (start, end);
    }

    /// <summary>
    ///     Builds two <see cref="IpRange"/> lookup tables (IPv4 + IPv6) from a collection of
    ///     CIDR strings (e.g. <c>"192.168.0.0/24"</c>, <c>"2001:db8::/32"</c>).
    ///     The constructor:
    ///     <ol>
    ///         <li>Parses every CIDR, validating the prefix length and IP literal.</li>
    ///         <li>Converts the network address into an <c>uint</c> (IPv4) or <c>BigInteger</c> (IPv6).</li>
    ///         <li>Derives the broadcast / last address with a bit-mask.</li>
    ///         <li>Stores each pair <c>(start, end)</c> in a list.</li>
    ///         <li>Merges overlapping or adjacent intervals so that the lookup lists are minimal
    ///             and sorted, enabling binary-search queries later.</li>
    ///     </ol>
    ///     The merged lists are cached in the private fields <c>_ipv4Ranges</c> and
    ///     <c>_ipv6Ranges</c> for lightning-fast membership tests.
    /// </summary>
    /// <param name="cidrs">Enumerable of CIDR strings. <c>null</c> yields an empty rule.</param>
    public IpRangeRule(IEnumerable<string> cidrs)
    {
        // Temporary interval buffers.
        var ipv4Intervals = new List<(uint start, uint end)>();
        var ipv6Intervals = new List<(BigInteger start, BigInteger end)>();

        foreach (var cidr in cidrs ?? Enumerable.Empty<string>())
        {
            // Split "IP/prefix".  If malformed, skip.
            var parts = cidr.Split('/');
            if (parts.Length != 2 || !int.TryParse(parts[1], out int prefix) || prefix < 0) continue;
            if (!IPAddress.TryParse(parts[0], out var ip)) continue;

            // IPv4 branch ────────────────────────────────────────────────────────────
            if (ip.AddressFamily == AddressFamily.InterNetwork)
            {
                uint start = IpToUInt(ip); // Network address
                uint mask = prefix == 0 ? 0 : ~(uint.MaxValue >> prefix); // Net mask
                ipv4Intervals.Add((start, start | mask)); // Add [start, end]
            }
            // IPv6 branch ────────────────────────────────────────────────────────────
            else if (ip.AddressFamily == AddressFamily.InterNetworkV6)
            {
                BigInteger start = IpToBigInteger(ip);
                BigInteger mask = prefix == 0
                    ? BigInteger.Zero
                    : (BigInteger.One << (128 - prefix)) - 1;
                ipv6Intervals.Add((start, start | mask));
            }
        }

        // Collapse the interval lists and cache the results.
        _ipv4Ranges = MergeIntervals(ipv4Intervals)
            .Select(r => new IpRange(r.start, r.end))
            .ToList();

        _ipv6Ranges = MergeIntervals(ipv6Intervals)
            .Select(r => new IpRange(r.start, r.end))
            .ToList();
    }

    private static uint IpToUInt(IPAddress ip)
    {
        var bytes = ip.GetAddressBytes();
        return ((uint) bytes[0] << 24) | ((uint) bytes[1] << 16) | ((uint) bytes[2] << 8) | bytes[3];
    }

    private static BigInteger IpToBigInteger(IPAddress ip)
    {
        return new BigInteger(ip.GetAddressBytes(), isUnsigned: true, isBigEndian: true);
    }

    /// <summary>
    ///     Merges a list of half-open intervals that may <b>touch or overlap</b> into the
    ///     minimal set of non-overlapping, <b>maximally extended</b> intervals.
    ///     Two intervals are considered mergeable when the <c>start</c> of the next interval
    ///     is <paramref name="currentEndPlusOne"/> (i.e., immediately adjacent) or falls inside
    ///     the current interval.
    /// </summary>
    /// <typeparam name="T">
    ///     A value type that implements <see cref="IComparable{T}"/> (e.g., <c>uint</c>,
    ///     <c>BigInteger</c>).  Only unsigned integral types are expected because the method
    ///     performs a <c>+ 1</c> operation on the upper bound.
    /// </typeparam>
    /// <param name="intervals">
    ///     Unordered list of intervals represented as tuples <c>(start, end)</c>,
    ///     where <c>start ≤ end</c>.
    /// </param>
    /// <returns>
    ///     A new list containing the merged intervals, sorted by <c>start</c>.
    /// </returns>
    private static List<(T start, T end)> MergeIntervals<T>(List<(T start, T end)> intervals)
        where T : IComparable<T>
    {
        // Nothing to merge when there are 0 or 1 intervals.
        if (intervals.Count <= 1) return intervals;

        // Sort intervals by their starting point to simplify the sweep.
        var sorted = intervals.OrderBy(i => i.start).ToList();
        var merged = new List<(T start, T end)>();

        // Keep a sliding "current" interval that we try to extend.
        var current = sorted[0];

        for (int i = 1; i < sorted.Count; i++)
        {
            T nextStart = sorted[i].start;

            // Compute (current.end + 1) in a type-safe way.
            //   • For uint    → cast to uint and add 1U.
            //   • Otherwise   → cast to BigInteger and add BigInteger.One.
            T currentEndPlusOne = typeof(T) == typeof(uint)
                ? (T) (object) ((uint) (object) current.end + 1U)
                : (T) (object) ((BigInteger) (object) current.end + BigInteger.One);

            // If the next interval begins before or exactly at (current.end + 1),
            // the two intervals overlap or touch → extend the current interval.
            if (nextStart.CompareTo(currentEndPlusOne) <= 0)
            {
                // New end is the greater of current.end and next.end.
                var maxEnd = Comparer<T>.Default.Compare(current.end, sorted[i].end) > 0
                    ? current.end
                    : sorted[i].end;

                current = (current.start, maxEnd);
            }
            else
            {
                // Gap detected → persist the current interval and start a new one.
                merged.Add(current);
                current = sorted[i];
            }
        }

        // Append the final in-progress interval.
        merged.Add(current);

        return merged;
    }

    /// <summary>
    ///     Evaluates a single request against the pre-computed IP ranges.
    /// </summary>
    /// <param name="request">Request metadata (must contain <c>ClientIp</c>).</param>
    /// <param name="cancellationToken">Cancellation token (unused).</param>
    /// <returns>
    ///     <see cref="AccessDecision.Block"/> if the client IP falls inside
    ///     any configured range, <see cref="AccessDecision.Allow"/> otherwise.
    ///     Returns <see cref="AccessDecision.Challenge"/> when the client IP is unknown.
    /// </returns>
    public ValueTask<AccessDecision> EvaluateAsync(
        RequestInfo request,
        CancellationToken cancellationToken = default)
    {
        // No IP → cannot decide confidently.
        if (request.ClientIp == null)
            return ValueTask.FromResult(AccessDecision.Challenge);

        var ip = request.ClientIp;

        // IPv4 lookup ───────────────────────────────────────────────────────────────
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            uint ipNum = IpToUInt(ip);
            if (IsInRange(_ipv4Ranges, ipNum))
                return ValueTask.FromResult(AccessDecision.Block);
        }
        // IPv6 lookup ───────────────────────────────────────────────────────────────
        else if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            BigInteger ipNum = IpToBigInteger(ip);
            if (IsInRange(_ipv6Ranges, ipNum))
                return ValueTask.FromResult(AccessDecision.Block);
        }

        // Default: allowed.
        return ValueTask.FromResult(AccessDecision.Allow);
    }

    /// <summary>
    ///     Binary-search helper for testing a numeric IP against a sorted, disjoint
    ///     list of <see cref="IpRange"/> objects.
    /// </summary>
    private static bool IsInRange<T>(List<IpRange> ranges, T ip) where T : IComparable<T>
    {
        // Locate the first range whose Start ≥ ip.
        int index = ranges.BinarySearch(
            new IpRange(ip, ip),
            Comparer<IpRange>.Create((a, b) => ((T) a.Start).CompareTo((T) b.Start)));

        if (index >= 0)
        {
            // Exact match on Start → check that ip ≤ End.
            return ip.CompareTo((T) ranges[index].End) <= 0;
        }

        // If not found, BinarySearch returns bitwise-complement of insertion index.
        index = ~index;

        // Candidate is the range immediately before the insertion point, if any.
        return index > 0 && ip.CompareTo((T) ranges[index - 1].End) <= 0;
    }
}