using Microsoft.AspNetCore.Mvc;
using Threatwatch.Api.Infrastructure;
using Threatwatch.Core.Services;

namespace Threatwatch.Api.Controllers;

[ApiController]
[Route("api/v1/technologies")]
public class TechnologiesController(TechnologyQueryService queries) : ControllerBase
{
    [HttpGet]
    public async Task<IActionResult> List([FromQuery] string? search = null, CancellationToken ct = default)
        => Ok(await queries.ListAsync(search, CurrentUser.Id(User), ct));

    [HttpGet("{slug}")]
    public async Task<IActionResult> Detail(string slug, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(slug))
        {
            return BadRequest(ApiError.Validation("'slug' must not be empty."));
        }

        var tech = await queries.GetBySlugAsync(slug, CurrentUser.Id(User), ct);
        if (tech is null)
        {
            return ApiError.ToResult(
                ApiError.NotFound($"Technology '{slug}' was not found."),
                StatusCodes.Status404NotFound);
        }

        return Ok(tech);
    }
}
