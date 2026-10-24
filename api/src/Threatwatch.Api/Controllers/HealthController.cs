using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Threatwatch.Core.Data;

namespace Threatwatch.Api.Controllers;

[ApiController]
[Route("api/v1/health")]
public class HealthController(ThreatwatchDbContext db) : ControllerBase
{
    /// <summary>Per-provider ingestion freshness/state from IngestionState.</summary>
    [HttpGet("providers")]
    public async Task<IActionResult> Providers(CancellationToken ct)
    {
        var states = await db.IngestionStates
            .OrderBy(s => s.Source)
            .Select(s => new
            {
                source = s.Source.ToString(),
                s.LastSuccessfulSyncAt,
                s.LastAttemptedSyncAt,
                s.LastError,
                s.LastDurationMs,
            })
            .ToListAsync(ct);

        return Ok(states);
    }
}
