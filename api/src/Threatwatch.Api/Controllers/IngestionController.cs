using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Threatwatch.Api.Infrastructure;
using Threatwatch.Ingestion.Workers;

namespace Threatwatch.Api.Controllers;

[ApiController]
[Route("api/v1/ingestion")]
public class IngestionController(IngestionRunner ingestion) : ControllerBase
{
    [HttpGet("sync")]
    public IActionResult Status() => Ok(ingestion.Status());

    [HttpPost("sync")]
    [RequireBrowserHeader]
    [EnableRateLimiting("writes")]
    public IActionResult Trigger() => Ok(ingestion.RequestSync());
}
