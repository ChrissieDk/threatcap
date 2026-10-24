using System.Security.Claims;

namespace Threatwatch.Api.Infrastructure;

public static class CurrentUser
{
    public static Guid Id(ClaimsPrincipal user)
    {
        var raw = user.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!Guid.TryParse(raw, out var id))
        {
            throw new InvalidOperationException("Authenticated user is missing a valid id claim.");
        }

        return id;
    }
}
