using System.Net;
using DotBarricade.Core.Interface;
using DotBarricade.Core.Model;
using DotBarricade.Core.Model.Enum;

namespace DotBarricade.Core.Rule;

public sealed class IpRangeRule(IEnumerable<string> cidrs) : IRule
{
    private readonly IReadOnlyList<IPNetwork> _blocked = cidrs.Select(IPNetwork.Parse).ToList();

    public ValueTask<AccessDecision> EvaluateAsync(RequestInfo request, CancellationToken cancellationToken = default)
    {
        // If client IP is not available, return a challenge decision
        if (request.ClientIp == null)
        {
            return ValueTask.FromResult(AccessDecision.Challenge);
        }

        // Check if client IP is within any of the blocked CIDR ranges
        var hit = _blocked.Any(net => net.Contains(request.ClientIp));

        // Return Block if matched, otherwise Allow
        return ValueTask.FromResult(hit ? AccessDecision.Block : AccessDecision.Allow);
    }
}