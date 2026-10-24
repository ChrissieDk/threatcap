using Microsoft.AspNetCore.Mvc;
using Threatwatch.Api.Infrastructure;
using Threatwatch.Core.Enums;
using Threatwatch.Core.Services;

namespace Threatwatch.Api.Controllers;

[ApiController]
[Route("api/v1/dashboard")]
public class DashboardController(DashboardService dashboard) : ControllerBase
{
    [HttpGet("summary")]
    public async Task<IActionResult> Summary(
        [FromQuery] int days = 7,
        [FromQuery] bool following = false,
        CancellationToken ct = default)
    {
        if (days is < 1 or > 365)
        {
            return ApiError.ToResult(ApiError.InvalidArgument("'days' must be between 1 and 365."), StatusCodes.Status400BadRequest);
        }

        return Ok(await dashboard.GetSummaryAsync(days, CurrentUser.Id(User), following, ct));
    }

    [HttpGet("daily")]
    public async Task<IActionResult> Daily(
        [FromQuery] int days = 7,
        [FromQuery] string metric = "disclosures",
        [FromQuery] bool following = false,
        CancellationToken ct = default)
    {
        if (days is < 1 or > 365)
        {
            return ApiError.ToResult(ApiError.InvalidArgument("'days' must be between 1 and 365."), StatusCodes.Status400BadRequest);
        }

        if (metric is not ("disclosures" or "updates" or "kev" or "incidents"))
        {
            return ApiError.ToResult(
                ApiError.InvalidArgument("'metric' must be one of disclosures|updates|kev|incidents."),
                StatusCodes.Status400BadRequest);
        }

        return Ok(await dashboard.GetDailyAsync(metric, days, CurrentUser.Id(User), following, ct));
    }

    [HttpGet("act-now")]
    public async Task<IActionResult> ActNow(
        [FromQuery] int top = 10,
        [FromQuery] int days = 30,
        CancellationToken ct = default)
    {
        if (top is < 1 or > 100)
        {
            return ApiError.ToResult(ApiError.InvalidArgument("'top' must be between 1 and 100."), StatusCodes.Status400BadRequest);
        }

        if (days is < 1 or > 365)
        {
            return ApiError.ToResult(ApiError.InvalidArgument("'days' must be between 1 and 365."), StatusCodes.Status400BadRequest);
        }

        return Ok(await dashboard.GetActNowAsync(top, days, CurrentUser.Id(User), ct));
    }
}
