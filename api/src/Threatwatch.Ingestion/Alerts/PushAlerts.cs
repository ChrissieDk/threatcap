using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Threatwatch.Core.Alerts;
using Threatwatch.Core.Data;
using Threatwatch.Core.Entities;
using Threatwatch.Core.Enums;
using WebPush;

namespace Threatwatch.Ingestion.Alerts;

/// <summary>
/// VAPID keys identify this server to browser push services. They are generated once,
/// encrypted with Data Protection and kept in the database so they survive restarts and
/// redeploys (losing them would silently orphan every browser subscription).
/// </summary>
public sealed class VapidKeyStore(
    IServiceScopeFactory scopeFactory,
    IDataProtectionProvider dataProtection,
    IOptions<AlertOptions> options)
{
    private const string SettingKey = "push.vapid";
    private readonly IDataProtector _protector = dataProtection.CreateProtector("Threatwatch.Vapid.v1");
    private readonly SemaphoreSlim _gate = new(1, 1);
    private VapidDetails? _cached;

    public async Task<VapidDetails> GetAsync(CancellationToken ct)
    {
        if (_cached is not null) return _cached;

        await _gate.WaitAsync(ct);
        try
        {
            if (_cached is not null) return _cached;

            await using var scope = scopeFactory.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<ThreatwatchDbContext>();
            var row = await db.AppSettings.FirstOrDefaultAsync(s => s.Key == SettingKey, ct);

            string publicKey, privateKey;
            if (row is not null)
            {
                var pair = JsonSerializer.Deserialize<string[]>(_protector.Unprotect(row.ProtectedValue))!;
                (publicKey, privateKey) = (pair[0], pair[1]);
            }
            else
            {
                var keys = VapidHelper.GenerateVapidKeys();
                (publicKey, privateKey) = (keys.PublicKey, keys.PrivateKey);
                db.AppSettings.Add(new AppSetting
                {
                    Key = SettingKey,
                    ProtectedValue = _protector.Protect(JsonSerializer.Serialize(new[] { publicKey, privateKey })),
                    UpdatedAt = DateTimeOffset.UtcNow,
                });
                await db.SaveChangesAsync(ct);
            }

            _cached = new VapidDetails(Subject(), publicKey, privateKey);
            return _cached;
        }
        finally
        {
            _gate.Release();
        }
    }

    private string Subject()
    {
        var configured = options.Value.PushSubject;
        if (!string.IsNullOrWhiteSpace(configured)) return configured;

        // Push services require a contact URL; fall back to the public web URL when it is https.
        return options.Value.WebBaseUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
            ? options.Value.WebBaseUrl
            : "mailto:admin@threatwatch.invalid";
    }
}

public sealed class BrowserPushAlertSender(
    VapidKeyStore vapid,
    IHttpClientFactory httpFactory,
    IOptions<AlertOptions> options) : IAlertSender
{
    public AlertChannelType Type => AlertChannelType.BrowserPush;

    public async Task SendAsync(AlertChannel channel, string? target, string? recipientEmail, AlertMessage message, CancellationToken ct)
    {
        PushTarget? push = null;
        if (target is not null)
        {
            try { push = JsonSerializer.Deserialize<PushTarget>(target); }
            catch (JsonException) { }
        }

        if (push is null) throw new AlertSendException("Browser subscription is invalid. Re-enable notifications.", permanent: true);

        var first = message.Items.FirstOrDefault();
        var body = first is null
            ? message.Subject
            : message.Items.Count + message.MoreCount > 1
                ? $"{first.Title} (+{message.Items.Count + message.MoreCount - 1} more)"
                : first.Title;
        var payload = JsonSerializer.Serialize(new
        {
            title = message.Subject,
            body,
            url = first?.Url ?? options.Value.WebBaseUrl,
        });

        var details = await vapid.GetAsync(ct);
        var client = new WebPushClient(httpFactory.CreateClient(AlertHttp.ClientName));
        try
        {
            await client.SendNotificationAsync(
                new PushSubscription(push.Endpoint, push.P256dh, push.Auth), payload, details, ct);
        }
        catch (WebPushException ex) when (ex.StatusCode is HttpStatusCode.Gone or HttpStatusCode.NotFound)
        {
            throw new AlertSendException("This browser unsubscribed. Enable notifications again.", permanent: true);
        }
        catch (WebPushException ex)
        {
            throw new AlertSendException($"Push service responded with HTTP {(int)ex.StatusCode}.");
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new AlertSendException("Push service timed out.");
        }
        catch (HttpRequestException)
        {
            throw new AlertSendException("Could not reach the push service.");
        }
    }
}
