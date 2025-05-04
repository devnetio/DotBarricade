namespace DotBarricade.Core.Model;

public sealed record RequestInfo(System.Net.IPAddress? ClientIp, string? CountryIso2, string? Host);