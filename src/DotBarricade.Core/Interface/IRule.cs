using DotBarricade.Core.Model;
using DotBarricade.Core.Model.Enum;

namespace DotBarricade.Core.Interface;

public interface IRule
{
    ValueTask<AccessDecision> EvaluateAsync(RequestInfo request, CancellationToken cancellationToken = default);
}