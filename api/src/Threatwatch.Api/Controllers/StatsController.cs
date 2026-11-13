using System.Globalization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Threatwatch.Core.Services;

namespace Threatwatch.Api.Controllers;

[ApiController]
[Route("api/v1/stats")]
public class StatsController(PublicStatsService stats, IConfiguration configuration) : ControllerBase
{
    /// <summary>
    /// Aggregate counts for the landing page. Needs the API key like every route, but no user session.
    /// <c>Stats:CountSince</c> (yyyy-MM-dd) sets where the counter starts.
    /// </summary>
    [AllowAnonymous]
    [HttpGet("public")]
    public async Task<IActionResult> Public(CancellationToken ct)
    {
        DateTimeOffset? since = DateTimeOffset.TryParseExact(
            configuration["Stats:CountSince"], "yyyy-MM-dd", CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal, out var parsed) ? parsed : null;

        return Ok(await stats.GetAsync(since, ct));
    }
}
