using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Threatwatch.Api.Infrastructure;
using Threatwatch.Core.Projects;

namespace Threatwatch.Api.Controllers;

public record CreateProjectRequest(string? Name, List<ProjectFileInput>? Files);

public record UpdateProjectFilesRequest(List<ProjectFileInput>? Files);

[ApiController]
[Route("api/v1/projects")]
[RequestSizeLimit(12_000_000)]
public class ProjectsController(ProjectService projects) : ControllerBase
{
    [HttpGet]
    public async Task<IActionResult> List(CancellationToken ct) =>
        Ok(await projects.ListAsync(CurrentUser.Id(User), ct));

    [HttpGet("overview")]
    public async Task<IActionResult> Overview([FromQuery] int top = 5, CancellationToken ct = default) =>
        Ok(await projects.OverviewAsync(CurrentUser.Id(User), top, ct));

    [HttpGet("supported-files")]
    public IActionResult SupportedFiles() => Ok(DependencyFileParser.SupportedFiles);

    [HttpGet("{id:guid}")]
    public async Task<IActionResult> Get(Guid id, CancellationToken ct)
    {
        var project = await projects.GetAsync(CurrentUser.Id(User), id, ct);
        return project is null ? NotFound() : Ok(project);
    }

    [HttpPost]
    [RequireBrowserHeader]
    [EnableRateLimiting("writes")]
    public async Task<IActionResult> Create([FromBody] CreateProjectRequest request, CancellationToken ct)
    {
        var (result, error) = await projects.CreateAsync(CurrentUser.Id(User), request.Name, request.Files, ct);
        return error is not null
            ? ApiError.ToResult(ApiError.InvalidArgument(error), StatusCodes.Status400BadRequest)
            : Ok(result);
    }

    [HttpPut("{id:guid}/files")]
    [RequireBrowserHeader]
    [EnableRateLimiting("writes")]
    public async Task<IActionResult> UpdateFiles(Guid id, [FromBody] UpdateProjectFilesRequest request, CancellationToken ct)
    {
        var (result, error, found) = await projects.UpdateFilesAsync(CurrentUser.Id(User), id, request.Files, ct);
        if (!found) return NotFound();
        return error is not null
            ? ApiError.ToResult(ApiError.InvalidArgument(error), StatusCodes.Status400BadRequest)
            : Ok(result);
    }

    [HttpDelete("{id:guid}")]
    [RequireBrowserHeader]
    [EnableRateLimiting("writes")]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct) =>
        await projects.DeleteAsync(CurrentUser.Id(User), id, ct) ? NoContent() : NotFound();
}
