using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Threatwatch.Api.Infrastructure;
using Threatwatch.Core.Services;

namespace Threatwatch.Api.Controllers;

[ApiController]
[Route("api/v1/notifications")]
public class NotificationsController(NotificationService notifications) : ControllerBase
{
    [HttpGet]
    public async Task<IActionResult> Get(CancellationToken ct) =>
        Ok(await notifications.GetAsync(CurrentUser.Id(User), ct));

    [HttpPost("read")]
    [RequireBrowserHeader]
    [EnableRateLimiting("writes")]
    public async Task<IActionResult> MarkAllRead(CancellationToken ct) =>
        Ok(await notifications.MarkAllReadAsync(CurrentUser.Id(User), ct));
}
