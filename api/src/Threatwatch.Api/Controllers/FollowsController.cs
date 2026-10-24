using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Threatwatch.Api.Infrastructure;
using Threatwatch.Core.Services;

namespace Threatwatch.Api.Controllers;

[ApiController]
[Route("api/v1/follows")]
[EnableRateLimiting("writes")]
public class FollowsController(FollowService follows) : ControllerBase
{
    private static readonly Regex SlugPattern = new("^[a-z0-9]+(?:-[a-z0-9]+)*$", RegexOptions.CultureInvariant | RegexOptions.Compiled, TimeSpan.FromMilliseconds(100));

    [HttpGet]
    public async Task<IActionResult> List([FromQuery] int days = FollowService.DefaultActivityDays, CancellationToken ct = default)
    {
        if (days is < 1 or > 365)
        {
            return ApiError.ToResult(ApiError.InvalidArgument("'days' must be between 1 and 365."), StatusCodes.Status400BadRequest);
        }

        return Ok(await follows.ListAsync(CurrentUser.Id(User), days, ct));
    }

    [HttpPost]
    [RequireBrowserHeader]
    public async Task<IActionResult> Follow([FromBody] FollowRequest? request, CancellationToken ct)
    {
        var userId = CurrentUser.Id(User);
        if (!string.IsNullOrWhiteSpace(request?.Slug))
        {
            if (!IsValidSlug(request.Slug))
            {
                return ApiError.ToResult(ApiError.Validation("'slug' is not a valid technology slug."), StatusCodes.Status400BadRequest);
            }

            var follow = await follows.FollowAsync(userId, request.Slug, ct);
            return follow is null
                ? ApiError.ToResult(ApiError.NotFound($"Technology '{request.Slug}' was not found."), StatusCodes.Status404NotFound)
                : Ok(follow);
        }

        if (string.IsNullOrWhiteSpace(request?.Ecosystem) || string.IsNullOrWhiteSpace(request.PackageName))
        {
            return ApiError.ToResult(
                ApiError.Validation("Provide a technology slug, or an ecosystem and package name."),
                StatusCodes.Status400BadRequest);
        }

        var created = await follows.FollowPackageAsync(userId, request.Ecosystem, request.PackageName, ct);
        return created is null
            ? ApiError.ToResult(ApiError.Validation("Ecosystem or package name is not valid."), StatusCodes.Status400BadRequest)
            : Ok(created);
    }

    [HttpPost("{slug}")]
    [RequireBrowserHeader]
    public Task<IActionResult> FollowBySlug(string slug, CancellationToken ct) =>
        Follow(new FollowRequest(slug, null, null), ct);

    [HttpDelete("{slug}")]
    [RequireBrowserHeader]
    public async Task<IActionResult> Unfollow(string slug, CancellationToken ct)
    {
        if (!IsValidSlug(slug))
        {
            return ApiError.ToResult(ApiError.Validation("'slug' is not a valid technology slug."), StatusCodes.Status400BadRequest);
        }

        var found = await follows.UnfollowAsync(CurrentUser.Id(User), slug, ct);
        if (!found)
        {
            return ApiError.ToResult(ApiError.NotFound($"Technology '{slug}' was not found."), StatusCodes.Status404NotFound);
        }

        return NoContent();
    }

    private static bool IsValidSlug(string slug) =>
        slug.Length is > 0 and <= 80 && SlugPattern.IsMatch(slug);

    public sealed record FollowRequest(string? Slug, string? Ecosystem, string? PackageName);
}
