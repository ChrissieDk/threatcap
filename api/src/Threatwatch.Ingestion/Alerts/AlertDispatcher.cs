using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Threatwatch.Core.Alerts;
using Threatwatch.Core.Data;
using Threatwatch.Core.Entities;
using Threatwatch.Core.Enums;

namespace Threatwatch.Ingestion.Alerts;

/// <summary>
/// Sends pending <see cref="AlertDelivery"/> rows. Everything pending for a channel goes out
/// as one message (instant mode) or one digest per day, with retry and exponential backoff.
/// A channel that fails repeatedly is disabled so a dead webhook is not hammered forever.
/// </summary>
public class AlertDispatcher(
    ThreatwatchDbContext db,
    AlertService alerts,
    IEnumerable<IAlertSender> senders,
    IOptions<AlertOptions> options,
    ILogger<AlertDispatcher> logger)
{
    public const int MaxConsecutiveFailures = 8;
    public static readonly TimeSpan DigestInterval = TimeSpan.FromHours(24);
    private static readonly TimeSpan MaxBackoff = TimeSpan.FromHours(6);
    private static readonly TimeSpan SentRetention = TimeSpan.FromDays(30);

    private readonly Dictionary<AlertChannelType, IAlertSender> _senders = senders.ToDictionary(s => s.Type);

    public async Task<int> DeliverPendingAsync(CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow;
        var opts = options.Value;

        var due = await db.AlertDeliveries
            .Where(d => d.SentAt == null && d.AbandonedAt == null && d.NextAttemptAt <= now && d.Channel.IsEnabled)
            .OrderBy(d => d.CreatedAt)
            .ToListAsync(ct);

        var sent = 0;
        foreach (var group in due.GroupBy(d => d.ChannelId))
        {
            ct.ThrowIfCancellationRequested();
            var channel = await db.AlertChannels.FirstAsync(c => c.Id == group.Key, ct);
            var mode = await db.AlertPreferences
                .Where(p => p.UserId == channel.UserId)
                .Select(p => (AlertDeliveryMode?)p.Mode)
                .FirstOrDefaultAsync(ct) ?? AlertDeliveryMode.Instant;

            if (mode == AlertDeliveryMode.DailyDigest && channel.LastDigestAt > now - DigestInterval)
            {
                continue;
            }

            var batch = group.ToList();
            var message = BuildMessage(batch, opts);
            var (error, permanent) = await TrySendAsync(channel, message, ct);
            RecordResult(channel, batch, error, permanent, now);
            if (error is null) sent++;
            await db.SaveChangesAsync(ct);
        }

        var cutoff = now - SentRetention;
        var expired = await db.AlertDeliveries
            .Where(d => (d.SentAt != null && d.SentAt < cutoff) || (d.AbandonedAt != null && d.AbandonedAt < cutoff))
            .ToListAsync(ct);
        if (expired.Count > 0)
        {
            db.AlertDeliveries.RemoveRange(expired);
            await db.SaveChangesAsync(ct);
        }

        return sent;
    }

    /// <summary>Sends a one-off message so users can confirm a channel works.</summary>
    public async Task<(bool Ok, bool Found, string? Error)> SendTestAsync(Guid userId, Guid channelId, CancellationToken ct)
    {
        var channel = await db.AlertChannels.FirstOrDefaultAsync(c => c.Id == channelId && c.UserId == userId, ct);
        if (channel is null)
        {
            return (false, false, null);
        }

        var message = new AlertMessage(
            "Threatwatch test alert",
            [new AlertMessageItem("Your alert channel is working.", "You will get alerts here when followed technologies match your rules.", null)],
            0,
            options.Value.WebBaseUrl.TrimEnd('/') + "/preferences");
        var (error, permanent) = await TrySendAsync(channel, message, ct);
        if (error is null)
        {
            channel.LastDeliveredAt = DateTimeOffset.UtcNow;
            channel.LastError = null;
            channel.ConsecutiveFailures = 0;
        }
        else
        {
            channel.LastError = error;
            if (permanent) channel.IsEnabled = false;
        }

        await db.SaveChangesAsync(ct);
        return (error is null, true, error);
    }

    private async Task<(string? Error, bool Permanent)> TrySendAsync(
        AlertChannel channel, AlertMessage message, CancellationToken ct)
    {
        if (!_senders.TryGetValue(channel.Type, out var sender))
        {
            return ("No sender for this channel type.", false);
        }

        try
        {
            string? email = null;
            if (channel.Type == AlertChannelType.Email)
            {
                var account = await db.Users
                    .Where(u => u.Id == channel.UserId)
                    .Select(u => new { u.Email, u.EmailConfirmed })
                    .FirstOrDefaultAsync(ct);
                if (account is not { EmailConfirmed: true })
                {
                    return ("Verify your email address to receive email alerts.", false);
                }

                email = account.Email;
            }

            await sender.SendAsync(channel, alerts.Unprotect(channel), email, message, ct);
            return (null, false);
        }
        catch (AlertSendException ex)
        {
            return (ex.Message, ex.Permanent);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            // Unexpected: log the detail server-side only; it may contain the target URL.
            logger.LogWarning(ex, "Alert send failed for channel {ChannelId} ({Type}).", channel.Id, channel.Type);
            return ("Unexpected error while sending.", false);
        }
    }

    private static void RecordResult(
        AlertChannel channel, List<AlertDelivery> batch, string? error, bool permanent, DateTimeOffset now)
    {
        if (error is null)
        {
            foreach (var d in batch) d.SentAt = now;
            channel.LastDeliveredAt = now;
            channel.LastDigestAt = now;
            channel.LastError = null;
            channel.ConsecutiveFailures = 0;
            return;
        }

        channel.ConsecutiveFailures++;
        channel.LastError = error.Length > 500 ? error[..500] : error;
        foreach (var d in batch)
        {
            d.Attempts++;
            var backoff = TimeSpan.FromMinutes(Math.Pow(2, Math.Min(d.Attempts, 10)));
            d.NextAttemptAt = now + (backoff > MaxBackoff ? MaxBackoff : backoff);
        }

        if (permanent || channel.ConsecutiveFailures >= MaxConsecutiveFailures)
        {
            channel.IsEnabled = false;
            channel.LastError = permanent ? channel.LastError : "Disabled after repeated failures. " + channel.LastError;
            foreach (var d in batch) d.AbandonedAt = now;
        }
    }

    public static AlertMessage BuildMessage(IReadOnlyList<AlertDelivery> batch, AlertOptions opts)
    {
        var shown = batch.Take(Math.Max(1, opts.MaxItemsPerMessage))
            .Select(d => new AlertMessageItem(d.Title, d.Summary, d.Url))
            .ToList();
        var subject = batch.Count == 1
            ? $"Threatwatch alert: {Shorten(batch[0].Title)}"
            : $"Threatwatch: {batch.Count} new alerts";
        return new AlertMessage(subject, shown, batch.Count - shown.Count, opts.WebBaseUrl.TrimEnd('/') + "/preferences");
    }

    private static string Shorten(string value) => value.Length <= 90 ? value : value[..89] + "…";
}
