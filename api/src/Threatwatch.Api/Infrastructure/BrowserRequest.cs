using Microsoft.AspNetCore.Mvc.Filters;

namespace Threatwatch.Api.Infrastructure;

public static class BrowserRequest
{
    public const string HeaderName = "X-Threatwatch-Request";

    public static bool IsPresent(HttpRequest request) =>
        request.Headers.TryGetValue(HeaderName, out var value) && value == "1";
}

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public sealed class RequireBrowserHeaderAttribute : ActionFilterAttribute
{
    public override void OnActionExecuting(ActionExecutingContext context)
    {
        if (!BrowserRequest.IsPresent(context.HttpContext.Request))
        {
            context.Result = ApiError.ToResult(
                ApiError.Validation($"Missing {BrowserRequest.HeaderName} header."),
                StatusCodes.Status400BadRequest);
        }
    }
}
