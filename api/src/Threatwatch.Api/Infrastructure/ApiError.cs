using Microsoft.AspNetCore.Mvc;

namespace Threatwatch.Api.Infrastructure;

/// <summary>Consistent error envelope: {"error":{"code","message"}}.</summary>
public record ApiError(string Code, string Message)
{
    public static ApiError NotFound(string message) => new("not_found", message);
    public static ApiError Validation(string message) => new("validation_error", message);
    public static ApiError InvalidArgument(string message) => new("invalid_argument", message);

    public static ObjectResult ToResult(ApiError error, int statusCode) =>
        new(new { error }) { StatusCode = statusCode };
}
