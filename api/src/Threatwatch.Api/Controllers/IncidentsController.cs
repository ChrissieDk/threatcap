using Microsoft.AspNetCore.Mvc;
using Threatwatch.Api.Infrastructure;
using Threatwatch.Core.Services;

namespace Threatwatch.Api.Controllers;

[ApiController]
[Route("api/v1/incidents")]
public class IncidentsController(IncidentQueryService incidents) : ControllerBase
{
    [HttpGet]
    public async Task<IActionResult> List(
        [FromQuery] int days = IncidentQueryService.DefaultDays,
        [FromQuery] int limit = IncidentQueryService.DefaultLimit,
        [FromQuery] bool following = true,
        CancellationToken ct = default)
    {
        if (days is < 1 or > 365)
        {
            return ApiError.ToResult(ApiError.InvalidArgument("'days' must be between 1 and 365."), StatusCodes.Status400BadRequest);
        }

        if (limit is < 1 or > 100)
        {
            return ApiError.ToResult(ApiError.InvalidArgument("'limit' must be between 1 and 100."), StatusCodes.Status400BadRequest);
        }

        return Ok(await incidents.ListAsync(days, limit, following, CurrentUser.Id(User), ct));
    }
}
