using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;
using Threatwatch.Api.Infrastructure;
using Threatwatch.Core.Alerts;
using Threatwatch.Ingestion.Alerts;

namespace Threatwatch.Api.Controllers;

public record SetChannelEnabledRequest(bool IsEnabled);

[ApiController]
[Route("api/v1/alerts")]
public class AlertsController(
    AlertService alerts,
    AlertDispatcher dispatcher,
    VapidKeyStore vapid,
    IOptions<SmtpOptions> smtp) : ControllerBase
{
    private bool EmailAvailable => smtp.Value.IsConfigured;

    [HttpGet]
    public async Task<IActionResult> Get(CancellationToken ct) =>
        Ok(await alerts.GetStateAsync(CurrentUser.Id(User), EmailAvailable, (await vapid.GetAsync(ct)).PublicKey, ct));

    [HttpPut("preferences")]
    [RequireBrowserHeader]
    [EnableRateLimiting("writes")]
    public async Task<IActionResult> SavePreferences([FromBody] SaveAlertPreferenceRequest request, CancellationToken ct)
    {
        var error = AlertService.ValidatePreference(request);
        if (error is not null)
        {
            return ApiError.ToResult(ApiError.InvalidArgument(error), StatusCodes.Status400BadRequest);
        }

        return Ok(await alerts.SavePreferenceAsync(CurrentUser.Id(User), request, ct));
    }

    [HttpPost("channels")]
    [RequireBrowserHeader]
    [EnableRateLimiting("writes")]
    public async Task<IActionResult> AddChannel([FromBody] CreateAlertChannelRequest request, CancellationToken ct)
    {
        var (channel, error) = await alerts.AddChannelAsync(CurrentUser.Id(User), request, EmailAvailable, ct);
        return error is not null
            ? ApiError.ToResult(ApiError.InvalidArgument(error), StatusCodes.Status400BadRequest)
            : Ok(channel);
    }

    [HttpPost("channels/push")]
    [RequireBrowserHeader]
    [EnableRateLimiting("writes")]
    public async Task<IActionResult> AddPushChannel([FromBody] CreatePushChannelRequest request, CancellationToken ct)
    {
        var (channel, error) = await alerts.AddPushChannelAsync(CurrentUser.Id(User), request, ct);
        return error is not null
            ? ApiError.ToResult(ApiError.InvalidArgument(error), StatusCodes.Status400BadRequest)
            : Ok(channel);
    }

    [HttpGet("channels/{id:guid}/setup")]
    public async Task<IActionResult> NtfySetup(Guid id, CancellationToken ct)
    {
        var setup = await alerts.GetNtfySetupAsync(CurrentUser.Id(User), id, ct);
        return setup is null ? NotFound() : Ok(setup);
    }

    [HttpPut("channels/{id:guid}")]
    [RequireBrowserHeader]
    [EnableRateLimiting("writes")]
    public async Task<IActionResult> SetEnabled(Guid id, [FromBody] SetChannelEnabledRequest request, CancellationToken ct) =>
        await alerts.SetEnabledAsync(CurrentUser.Id(User), id, request.IsEnabled, ct) ? NoContent() : NotFound();

    [HttpDelete("channels/{id:guid}")]
    [RequireBrowserHeader]
    [EnableRateLimiting("writes")]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct) =>
        await alerts.DeleteChannelAsync(CurrentUser.Id(User), id, ct) ? NoContent() : NotFound();

    [HttpPost("channels/{id:guid}/test")]
    [RequireBrowserHeader]
    [EnableRateLimiting("auth")]
    public async Task<IActionResult> Test(Guid id, CancellationToken ct)
    {
        var (ok, found, error) = await dispatcher.SendTestAsync(CurrentUser.Id(User), id, ct);
        if (!found) return NotFound();
        return Ok(new { ok, error });
    }
}
