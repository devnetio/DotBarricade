using DotBarricade.Core.Interface;
using DotBarricade.Core.Model;
using DotBarricade.Core.Model.Enum;

namespace DotBarricade.Core.Service;

public class FirewallService(IEnumerable<IRule> rules) : IFirewall
{
    private readonly IReadOnlyList<IRule> _rules = rules.ToList();

    public async ValueTask<AccessDecision> EvaluateAsync(RequestInfo request,
        CancellationToken cancellationToken = default)
    {
        // Start with the default decision.
        var decision = AccessDecision.Allow;
        
        // Evaluate each rule in order.
        foreach (var rule in _rules)
        {
            var newDecision = await rule.EvaluateAsync(request, cancellationToken);
            
            // Update decision if the current rule gives a higher impact.
            if (newDecision > decision)
            {
                decision = newDecision;
            }

            // Early exit if a blocking decision is reached.
            if (decision == AccessDecision.Block)
            {
                return decision;
            }
        }

        return decision;
    }
}