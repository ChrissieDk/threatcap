using Microsoft.AspNetCore.Mvc;
using Threatwatch.Api.Infrastructure;
using Threatwatch.Core.Enums;
using Threatwatch.Core.Services;

namespace Threatwatch.Api.Controllers;

[ApiController]
[Route("api/v1/vulnerabilities")]
public class VulnerabilitiesController(VulnerabilityQueryService queries) : ControllerBase
{
    [HttpGet]
    public async Task<IActionResult> List(
        [FromQuery] string? search = null,
        [FromQuery] string? severity = null,
        [FromQuery] string? ecosystem = null,
        [FromQuery] bool? kev = null,
        [FromQuery] bool? fix = null,
        [FromQuery] string? from = null,
        [FromQuery] string? to = null,
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 25,
        [FromQuery] string sort = "-publishedAt",
        [FromQuery] bool following = false,
        [FromQuery] string? tech = null,
        CancellationToken ct = default)
    {
        if (page < 1)
        {
            return BadRequest(ApiError.Validation("'page' must be >= 1."));
        }

        if (pageSize is < 1 or > 100)
        {
            return BadRequest(ApiError.Validation("'pageSize' must be between 1 and 100."));
        }

        if (!TryParseDate(from, out var fromDate) || !TryParseDate(to, out var toDate))
        {
            return BadRequest(ApiError.Validation("'from' and 'to' must be yyyy-MM-dd dates."));
        }

        if (fromDate.HasValue && toDate.HasValue && fromDate > toDate)
        {
            return BadRequest(ApiError.Validation("'from' must not be after 'to'."));
        }

        if (!string.IsNullOrWhiteSpace(severity)
            && !Enum.TryParse<Severity>(severity, ignoreCase: true, out _))
        {
            return BadRequest(ApiError.Validation(
                $"'{severity}' is not a valid severity (Critical|High|Medium|Low|Unknown)."));
        }

        if (!string.IsNullOrWhiteSpace(ecosystem)
            && !Enum.TryParse<Ecosystem>(ecosystem, ignoreCase: true, out _))
        {
            return BadRequest(ApiError.Validation(
                $"'{ecosystem}' is not a valid ecosystem (Npm|NuGet|PyPI|Maven|Cargo|Go|GithubActions|Linux|Other)."));
        }

        if (!string.IsNullOrWhiteSpace(tech)
            && (tech.Length > 80 || tech.Contains('/', StringComparison.Ordinal) || tech.Contains('\\', StringComparison.Ordinal)))
        {
            return BadRequest(ApiError.Validation("'tech' is not a valid technology slug."));
        }

        var result = await queries.ListAsync(
            search, severity, ecosystem, kev, fix, fromDate, toDate, page, pageSize, sort,
            following, tech, CurrentUser.Id(User), ct);
        return Ok(result);
    }

    [HttpGet("{id}")]
    public async Task<IActionResult> Detail(string id, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(id))
        {
            return BadRequest(ApiError.Validation("'id' must not be empty."));
        }

        var detail = await queries.GetByIdAsync(id, ct);
        if (detail is null)
        {
            return ApiError.ToResult(
                ApiError.NotFound($"Vulnerability '{id}' was not found."),
                StatusCodes.Status404NotFound);
        }

        return Ok(detail);
    }

    private static bool TryParseDate(string? value, out DateTimeOffset? date)
    {
        date = null;
        if (string.IsNullOrWhiteSpace(value))
        {
            return true;
        }

        if (!DateTimeOffset.TryParseExact(value, "yyyy-MM-dd",
                System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.AssumeUniversal, out var parsed))
        {
            return false;
        }

        date = parsed;
        return true;
    }
}
