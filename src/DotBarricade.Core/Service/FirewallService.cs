using DotBarricade.Core.Interface;
using DotBarricade.Core.Model;
using DotBarricade.Core.Model.Enum;

namespace DotBarricade.Core.Service;

public class FirewallService : IFirewall
{
    private readonly IReadOnlyList<IRule> _rules;

    public FirewallService(IEnumerable<IRule> rules)
    {
        _rules = rules.ToList();
    }


    /// <summary>
    /// Runs the configured <see cref="IRule"/> instances against the supplied
    /// <paramref name="request"/> and returns the most restrictive
    /// <see cref="AccessDecision"/> produced.  
    /// Evaluation short-circuits as soon as a rule returns
    /// <see cref="AccessDecision.Block"/> for maximum performance.
    /// </summary>
    /// <param name="request">
    /// Immutable snapshot of the client IP, host, country code and headers for the
    /// HTTP request under evaluation.
    /// </param>
    /// <param name="cancellationToken">
    /// Token that propagates notification that the operation should be cancelled.
    /// </param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> whose result is:
    /// <list type="bullet">
    ///   <item><see cref="AccessDecision.Allow"/> – all rules passed.</item>
    ///   <item><see cref="AccessDecision.Challenge"/> – at least one rule signalled a soft block.</item>
    ///   <item><see cref="AccessDecision.Block"/> – a rule blocked the request (evaluation halted).</item>
    /// </list>
    /// </returns>
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