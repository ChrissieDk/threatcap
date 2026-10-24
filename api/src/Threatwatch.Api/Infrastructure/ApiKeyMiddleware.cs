using System.Security.Cryptography;
using System.Text;

namespace Threatwatch.Api.Infrastructure;

/// <summary>
/// Service gate for /api. The browser never sees this key; Next.js attaches it.
/// It does not create a user principal — signed-in users are the cookie session.
/// </summary>
public class ApiKeyMiddleware(RequestDelegate next, IConfiguration configuration)
{
    private const string BearerPrefix = "Bearer ";
    private readonly byte[] _expectedHash = SHA256.HashData(
        Encoding.UTF8.GetBytes(configuration["Auth:ApiKey"]
            ?? throw new InvalidOperationException("Auth:ApiKey is not configured.")));

    public async Task InvokeAsync(HttpContext context)
    {
        if (context.Request.Path.StartsWithSegments("/api") && !IsValid(context))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsJsonAsync(new
            {
                error = new
                {
                    code = "unauthorized",
                    message = "A valid API key is required.",
                },
            });
            return;
        }

        await next(context);
    }

    private bool IsValid(HttpContext context)
    {
        if (!context.Request.Headers.TryGetValue("Authorization", out var headerValues))
        {
            return false;
        }

        var header = headerValues.ToString();
        if (!header.StartsWith(BearerPrefix, StringComparison.Ordinal) || header.Length == BearerPrefix.Length)
        {
            return false;
        }

        var providedHash = SHA256.HashData(Encoding.UTF8.GetBytes(header[BearerPrefix.Length..]));
        return CryptographicOperations.FixedTimeEquals(providedHash, _expectedHash);
    }
}
