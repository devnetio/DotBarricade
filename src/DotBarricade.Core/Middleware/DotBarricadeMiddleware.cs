using System.Net;
using DotBarricade.Core.Interface;
using DotBarricade.Core.Model;
using DotBarricade.Core.Model.Enum;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace DotBarricade.Core.Middleware;

public class DotBarricadeMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IFirewall _firewall;
    private readonly IHostnameResolver _hostnameResolver;
    private readonly ILogger<DotBarricadeMiddleware> _logger;

    public DotBarricadeMiddleware(
        RequestDelegate next,
        IFirewall firewall,
        ILogger<DotBarricadeMiddleware> logger,
        IHostnameResolver hostnameResolver)
    {
        _next = next ?? throw new ArgumentNullException(nameof(next));
        _firewall = firewall ?? throw new ArgumentNullException(nameof(firewall));
        _logger = logger;
        _hostnameResolver = hostnameResolver;
    }

    public async ValueTask InvokeAsync(HttpContext context)
    {
        var clientIp = context.Connection.RemoteIpAddress;

        IDictionary<string, string> headers = context.Request.Headers.ToDictionary(
            kvp => kvp.Key,
            kvp => kvp.Value.ToString(),
            StringComparer.OrdinalIgnoreCase);

        var host = clientIp != null ? await _hostnameResolver.ResolveAsync(clientIp, context.RequestAborted) : null;

        var requestInfo = new RequestInfo(clientIp, null, host, headers);

        var decision = await _firewall.EvaluateAsync(requestInfo, context.RequestAborted);

        if (decision == AccessDecision.Block)
        {
            _logger.LogInformation("DotBarricade blocked request {Method} {Path} from {Ip}.",
                context.Request.Method,
                context.Request.Path,
                clientIp);

            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return;
        }

        await _next(context);
    }
}