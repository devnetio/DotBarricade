using DotBarricade.Core.Model;

namespace DotBarricade.Core.Blocking;

public interface IRule
{
    bool IsMatch(RequestInfo request);
}