using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Threatwatch.Core.Data;
using Threatwatch.Core.Entities;
using Threatwatch.Core.Enums;
using Threatwatch.Core.Projects;
using Threatwatch.Core.Services;

namespace Threatwatch.Core.Alerts;

public record AlertPreferenceDto(
    Severity MinSeverity,
    bool AlwaysAlertKnownExploited,
    double? MinEpss,
    bool IncludeIncidents,
    AlertDeliveryMode Mode);

public record AlertChannelDto(
    Guid Id,
    AlertChannelType Type,
    string Label,
    string? TargetHint,
    bool IsEnabled,
    DateTimeOffset? LastDeliveredAt,
    string? LastError);

public record AlertStateDto(
    AlertPreferenceDto Preference,
    IReadOnlyList<AlertChannelDto> Channels,
    bool EmailAvailable,
    bool EmailVerified,
    string? Email,
    int FollowedCount,
    string? PushPublicKey);

public record NtfySetupDto(string TopicUrl, string Server, string Topic);

public record PushTarget(string Endpoint, string P256dh, string Auth);

public record CreatePushChannelRequest(string? Endpoint, string? P256dh, string? Auth, string? Label);

public record SaveAlertPreferenceRequest(
    Severity MinSeverity,
    bool AlwaysAlertKnownExploited,
    double? MinEpss,
    bool IncludeIncidents,
    AlertDeliveryMode Mode);

public record CreateAlertChannelRequest(AlertChannelType Type, string? Label, string? Target);

/// <summary>
/// Alert preferences, channels (with encrypted destinations) and the enqueue step that
/// turns newly matching vulnerabilities and incidents into pending <see cref="AlertDelivery"/>
/// rows. Sending lives in the ingestion project so this stays free of transport concerns.
/// </summary>
public class AlertService(
    ThreatwatchDbContext db,
    IDataProtectionProvider dataProtection,
    IOptions<AlertOptions> options)
{
    private const string ProtectorPurpose = "Threatwatch.AlertChannel.v1";

    private readonly IDataProtector _protector = dataProtection.CreateProtector(ProtectorPurpose);

    public static AlertPreferenceDto Defaults { get; } =
        new(Severity.High, true, null, false, AlertDeliveryMode.Instant);

    public string? Unprotect(AlertChannel channel) =>
        channel.ProtectedTarget is null ? null : _protector.Unprotect(channel.ProtectedTarget);

    public async Task<AlertStateDto> GetStateAsync(
        Guid userId, bool emailAvailable, string? pushPublicKey, CancellationToken ct)
    {
        var account = await db.Users.AsNoTracking()
            .Where(u => u.Id == userId)
            .Select(u => new { u.Email, u.EmailConfirmed })
            .FirstOrDefaultAsync(ct);
        var followed = await db.UserFollows.CountAsync(f => f.UserId == userId, ct);
        var pref = await db.AlertPreferences.AsNoTracking().FirstOrDefaultAsync(p => p.UserId == userId, ct);
        var channels = await db.AlertChannels.AsNoTracking()
            .Where(c => c.UserId == userId)
            .OrderBy(c => c.CreatedAt)
            .ToListAsync(ct);

        return new AlertStateDto(
            pref is null ? Defaults : ToDto(pref),
            channels.Select(ToDto).ToList(),
            emailAvailable,
            account?.EmailConfirmed ?? false,
            account?.Email,
            followed,
            pushPublicKey);
    }

    public async Task<AlertPreferenceDto> SavePreferenceAsync(
        Guid userId, SaveAlertPreferenceRequest request, CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow;
        var pref = await db.AlertPreferences.FirstOrDefaultAsync(p => p.UserId == userId, ct);
        if (pref is null)
        {
            pref = new AlertPreference { Id = Guid.NewGuid(), UserId = userId, CreatedAt = now };
            db.AlertPreferences.Add(pref);
        }

        pref.MinSeverity = request.MinSeverity;
        pref.AlwaysAlertKnownExploited = request.AlwaysAlertKnownExploited;
        pref.MinEpss = request.MinEpss;
        pref.IncludeIncidents = request.IncludeIncidents;
        pref.Mode = request.Mode;
        pref.UpdatedAt = now;
        await db.SaveChangesAsync(ct);
        return ToDto(pref);
    }

    public static string? ValidatePreference(SaveAlertPreferenceRequest request)
    {
        if (!Enum.IsDefined(request.MinSeverity) || request.MinSeverity == Severity.Unknown)
        {
            return "'minSeverity' must be Low, Medium, High or Critical.";
        }

        if (!Enum.IsDefined(request.Mode))
        {
            return "'mode' is not valid.";
        }

        if (request.MinEpss is < 0 or > 1)
        {
            return "'minEpss' must be between 0 and 1.";
        }

        return null;
    }

    public async Task<(AlertChannelDto? Channel, string? Error)> AddChannelAsync(
        Guid userId, CreateAlertChannelRequest request, bool emailAvailable, CancellationToken ct)
    {
        if (!Enum.IsDefined(request.Type))
        {
            return (null, "Unknown channel type.");
        }

        if (await db.AlertChannels.CountAsync(c => c.UserId == userId, ct) >= AlertOptions.MaxChannelsPerUser)
        {
            return (null, $"You can have at most {AlertOptions.MaxChannelsPerUser} channels.");
        }

        var label = request.Label?.Trim();
        string? protectedTarget = null;
        string? hint = null;

        if (request.Type == AlertChannelType.Email)
        {
            if (!emailAvailable)
            {
                return (null, "Email alerts are not configured on this server.");
            }

            if (!await db.Users.AnyAsync(u => u.Id == userId && u.EmailConfirmed, ct))
            {
                return (null, "Verify your email address before enabling email alerts.");
            }

            label = string.IsNullOrEmpty(label) ? "Email" : label;
        }
        else if (request.Type == AlertChannelType.BrowserPush)
        {
            return (null, "Use the browser push endpoint to register this browser.");
        }
        else
        {
            var rawTarget = request.Target;
            var generated = request.Type == AlertChannelType.Ntfy && string.IsNullOrWhiteSpace(rawTarget);
            if (generated)
            {
                rawTarget = GenerateNtfyTopicUrl(options.Value.NtfyServerUrl);
                label = string.IsNullOrEmpty(label) ? "Phone (ntfy)" : label;
            }

            if (!OutboundUrlPolicy.TryParse(rawTarget, options.Value.AllowPrivateTargets, out var uri, out var error))
            {
                return (null, error);
            }

            if (!generated && !options.Value.AllowPrivateTargets && !await OutboundUrlPolicy.ResolvesPubliclyAsync(uri, ct))
            {
                return (null, "URL host could not be resolved to a public address.");
            }

            protectedTarget = _protector.Protect(uri.ToString());
            hint = uri.Host;
            label = string.IsNullOrEmpty(label) ? request.Type.ToString() : label;
        }

        if (label.Length > 80)
        {
            return (null, "Label must be at most 80 characters.");
        }

        var channel = new AlertChannel
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            Type = request.Type,
            Label = label,
            ProtectedTarget = protectedTarget,
            TargetHint = hint,
            CreatedAt = DateTimeOffset.UtcNow,
        };
        db.AlertChannels.Add(channel);

        await EnsureDefaultPreferenceAsync(userId, ct);
        await db.SaveChangesAsync(ct);
        return (ToDto(channel), null);
    }

    /// <summary>Registers (or refreshes) a browser's Web Push subscription as a channel.</summary>
    public async Task<(AlertChannelDto? Channel, string? Error)> AddPushChannelAsync(
        Guid userId, CreatePushChannelRequest request, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.P256dh) || string.IsNullOrWhiteSpace(request.Auth)
            || request.P256dh.Length > 200 || request.Auth.Length > 100)
        {
            return (null, "Push subscription keys are missing or invalid.");
        }

        // Push endpoints are chosen by the browser, so they get the same SSRF checks as webhooks.
        if (!OutboundUrlPolicy.TryParse(request.Endpoint, allowPrivate: false, out var uri, out var error))
        {
            return (null, error);
        }

        if (!await OutboundUrlPolicy.ResolvesPubliclyAsync(uri, ct))
        {
            return (null, "Push endpoint could not be resolved to a public address.");
        }

        var existing = await db.AlertChannels
            .Where(c => c.UserId == userId && c.Type == AlertChannelType.BrowserPush)
            .ToListAsync(ct);
        var channel = existing.FirstOrDefault(c =>
            ReadPushTarget(c)?.Endpoint == uri.ToString());

        var label = string.IsNullOrWhiteSpace(request.Label) ? "This browser" : request.Label.Trim();
        if (label.Length > 80) label = label[..80];

        if (channel is null)
        {
            if (await db.AlertChannels.CountAsync(c => c.UserId == userId, ct) >= AlertOptions.MaxChannelsPerUser)
            {
                return (null, $"You can have at most {AlertOptions.MaxChannelsPerUser} channels.");
            }

            channel = new AlertChannel
            {
                Id = Guid.NewGuid(),
                UserId = userId,
                Type = AlertChannelType.BrowserPush,
                Label = label,
                CreatedAt = DateTimeOffset.UtcNow,
            };
            db.AlertChannels.Add(channel);
        }

        channel.Label = label;
        channel.ProtectedTarget = _protector.Protect(
            System.Text.Json.JsonSerializer.Serialize(new PushTarget(uri.ToString(), request.P256dh, request.Auth)));
        channel.TargetHint = uri.Host;
        channel.IsEnabled = true;
        channel.ConsecutiveFailures = 0;
        channel.LastError = null;

        await EnsureDefaultPreferenceAsync(userId, ct);
        await db.SaveChangesAsync(ct);
        return (ToDto(channel), null);
    }

    public PushTarget? ReadPushTarget(AlertChannel channel)
    {
        try
        {
            var raw = Unprotect(channel);
            return raw is null ? null : System.Text.Json.JsonSerializer.Deserialize<PushTarget>(raw);
        }
        catch (Exception ex) when (ex is System.Security.Cryptography.CryptographicException or System.Text.Json.JsonException)
        {
            return null;
        }
    }

    /// <summary>Lets users re-open the subscribe instructions for a generated ntfy topic.</summary>
    public async Task<NtfySetupDto?> GetNtfySetupAsync(Guid userId, Guid channelId, CancellationToken ct)
    {
        var channel = await db.AlertChannels.AsNoTracking()
            .FirstOrDefaultAsync(c => c.Id == channelId && c.UserId == userId && c.Type == AlertChannelType.Ntfy, ct);
        var url = channel is null ? null : Unprotect(channel);
        if (url is null || !Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return null;
        }

        var server = uri.GetLeftPart(UriPartial.Authority);
        return new NtfySetupDto(uri.ToString(), server, uri.AbsolutePath.Trim('/'));
    }

    private static string GenerateNtfyTopicUrl(string server)
    {
        // 128 bits of randomness: the topic name is the only secret protecting the feed.
        var topic = "peregrinet-" + Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        return server.TrimEnd('/') + "/" + topic;
    }

    private async Task EnsureDefaultPreferenceAsync(Guid userId, CancellationToken ct)
    {
        // Alerts only start flowing once a user has rules; make sure defaults exist so a
        // fresh channel works without a separate "save" step.
        if (await db.AlertPreferences.AnyAsync(p => p.UserId == userId, ct))
        {
            return;
        }

        var now = DateTimeOffset.UtcNow;
        db.AlertPreferences.Add(new AlertPreference
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            MinSeverity = Defaults.MinSeverity,
            AlwaysAlertKnownExploited = Defaults.AlwaysAlertKnownExploited,
            Mode = Defaults.Mode,
            CreatedAt = now,
            UpdatedAt = now,
        });
    }

    public async Task<bool> SetEnabledAsync(Guid userId, Guid channelId, bool enabled, CancellationToken ct)
    {
        var channel = await db.AlertChannels.FirstOrDefaultAsync(c => c.Id == channelId && c.UserId == userId, ct);
        if (channel is null)
        {
            return false;
        }

        channel.IsEnabled = enabled;
        if (enabled)
        {
            channel.ConsecutiveFailures = 0;
            channel.LastError = null;
        }

        await db.SaveChangesAsync(ct);
        return true;
    }

    public async Task<bool> DeleteChannelAsync(Guid userId, Guid channelId, CancellationToken ct)
    {
        var channel = await db.AlertChannels.FirstOrDefaultAsync(c => c.Id == channelId && c.UserId == userId, ct);
        if (channel is null)
        {
            return false;
        }

        db.AlertChannels.Remove(channel);
        await db.SaveChangesAsync(ct);
        return true;
    }

    /// <summary>
    /// Creates pending deliveries for every enabled channel whose owner follows a matching,
    /// rule-passing item. Idempotent via the (channel, kind, item) unique key.
    /// </summary>
    public async Task<int> EnqueueAsync(CancellationToken ct)
    {
        var opts = options.Value;
        var now = DateTimeOffset.UtcNow;
        var floor = now.AddDays(-Math.Max(1, opts.LookbackDays));

        var channels = await db.AlertChannels.AsNoTracking().Where(c => c.IsEnabled).ToListAsync(ct);
        if (channels.Count == 0)
        {
            return 0;
        }

        var userIds = channels.Select(c => c.UserId).Distinct().ToList();
        var prefs = await db.AlertPreferences.AsNoTracking()
            .Where(p => userIds.Contains(p.UserId))
            .ToDictionaryAsync(p => p.UserId, ct);
        if (prefs.Count == 0)
        {
            return 0;
        }

        var since = prefs.Values.Min(p => p.CreatedAt);
        since = since > floor ? since : floor;

        var recent = await db.Vulnerabilities.AsNoTracking()
            .Where(v => !v.IsWithdrawn
                && (v.PublishedAt >= since
                    || v.Events.Any(e => e.EventType == VulnerabilityEventType.KnownExploitedAdded && e.EventAt >= since)))
            .Select(v => new
            {
                v.Id,
                v.CanonicalId,
                v.Title,
                v.Severity,
                v.CvssScore,
                v.EpssScore,
                v.IsKnownExploited,
                v.PublishedAt,
                Packages = v.AffectedPackages.Select(p => new { p.Ecosystem, p.PackageName, p.DisplayName, p.AffectedRanges }).ToList(),
                KevAddedAt = v.Events
                    .Where(e => e.EventType == VulnerabilityEventType.KnownExploitedAdded)
                    .Select(e => (DateTimeOffset?)e.EventAt)
                    .FirstOrDefault(),
            })
            .ToListAsync(ct);

        var projectDepsByUser = await ProjectService.LoadMergedAsync(db, userIds, ct);
        var triaged = await TriageService.ActiveAsync(db, userIds, ct);

        var created = 0;
        foreach (var userId in userIds)
        {
            if (!prefs.TryGetValue(userId, out var pref))
            {
                continue;
            }

            var follows = await db.UserFollows.AsNoTracking()
                .Where(f => f.UserId == userId)
                .Select(f => f.Technology)
                .ToListAsync(ct);
            var projectDeps = projectDepsByUser.GetValueOrDefault(userId) ?? [];
            if (follows.Count == 0 && projectDeps.Count == 0)
            {
                continue;
            }

            var depIndex = projectDeps.ToLookup(d => (d.Ecosystem, d.Name));
            var userChannels = channels.Where(c => c.UserId == userId).ToList();
            var candidates = new List<(AlertItemKind Kind, Guid Id, string Title, string? Summary, string? Url)>();

            foreach (var v in recent)
            {
                var activityAt = v.KevAddedAt > v.PublishedAt ? v.KevAddedAt!.Value : v.PublishedAt;
                if (activityAt < pref.CreatedAt || activityAt < floor || !Passes(pref, v.Severity, v.IsKnownExploited, v.EpssScore))
                {
                    continue;
                }

                // A version-checked hit in one of the user's projects is the most specific reason.
                string? reason = null;
                foreach (var p in v.Packages)
                {
                    foreach (var dep in depIndex[(p.Ecosystem, p.PackageName)])
                    {
                        if (triaged.ContainsKey((dep.ProjectId, v.Id))) continue;
                        var check = OsvRangeEvaluator.Evaluate(p.Ecosystem, p.AffectedRanges, dep.Version);
                        if (check.Verdict != RangeVerdict.Affected) continue;
                        reason = $"affects {dep.ProjectName}: {dep.DisplayName} {dep.Version}"
                            + (check.FixedIn is null ? "" : $" (fixed in {check.FixedIn})");
                        break;
                    }

                    if (reason is not null) break;
                }

                if (reason is null)
                {
                    var matched = follows.FirstOrDefault(t => v.Packages.Any(p =>
                        TechnologyPackageMatcher.Matches(t, p.Ecosystem, p.PackageName, p.DisplayName)));
                    if (matched is null)
                    {
                        continue;
                    }

                    reason = $"affects {matched.Name}";
                }

                var facts = new List<string> { v.Severity.ToString() };
                if (v.CvssScore is { } cvss) facts.Add($"CVSS {cvss:0.#}");
                if (v.EpssScore is { } epss) facts.Add($"EPSS {epss:P1}");
                if (v.IsKnownExploited) facts.Add("Known exploited (CISA KEV)");
                facts.Add(reason);

                candidates.Add((
                    AlertItemKind.Vulnerability,
                    v.Id,
                    $"{v.CanonicalId}: {v.Title}",
                    string.Join(" · ", facts),
                    $"{opts.WebBaseUrl.TrimEnd('/')}/vulnerabilities/{v.Id}"));
            }

            if (pref.IncludeIncidents)
            {
                var incidentSince = pref.CreatedAt > floor ? pref.CreatedAt : floor;
                var incidents = await db.SecurityIncidents.AsNoTracking()
                    .Where(i => i.StartedAt >= incidentSince && i.Status != IncidentStatus.Resolved)
                    .WhereMatchesFollows(follows)
                    .ToListAsync(ct);
                candidates.AddRange(incidents.Select(i => (
                    AlertItemKind.Incident,
                    i.Id,
                    $"{i.VendorName}: {i.Title}",
                    $"{i.Type} · {i.Status}",
                    i.Url)));
            }

            if (candidates.Count == 0)
            {
                continue;
            }

            var channelIds = userChannels.Select(c => c.Id).ToList();
            var itemIds = candidates.Select(c => c.Id).ToList();
            var existing = (await db.AlertDeliveries.AsNoTracking()
                    .Where(d => channelIds.Contains(d.ChannelId) && itemIds.Contains(d.ItemId))
                    .Select(d => new { d.ChannelId, d.ItemKind, d.ItemId })
                    .ToListAsync(ct))
                .Select(d => (d.ChannelId, d.ItemKind, d.ItemId))
                .ToHashSet();

            foreach (var channel in userChannels)
            {
                foreach (var c in candidates)
                {
                    if (existing.Contains((channel.Id, c.Kind, c.Id)))
                    {
                        continue;
                    }

                    db.AlertDeliveries.Add(new AlertDelivery
                    {
                        Id = Guid.NewGuid(),
                        ChannelId = channel.Id,
                        ItemKind = c.Kind,
                        ItemId = c.Id,
                        Title = Truncate(c.Title, 300),
                        Summary = c.Summary is null ? null : Truncate(c.Summary, 600),
                        Url = c.Url is { Length: <= 500 } ? c.Url : null,
                        CreatedAt = now,
                        NextAttemptAt = now,
                    });
                    created++;
                }
            }

            try
            {
                await db.SaveChangesAsync(ct);
            }
            catch (DbUpdateException)
            {
                // A concurrent run already enqueued some of these; the unique key kept it safe.
                db.ChangeTracker.Clear();
            }
        }

        return created;
    }

    public static bool Passes(AlertPreference pref, Severity severity, bool isKnownExploited, double? epss)
    {
        if (isKnownExploited && pref.AlwaysAlertKnownExploited)
        {
            return true;
        }

        if (severity < pref.MinSeverity)
        {
            return false;
        }

        return pref.MinEpss is not { } min || (epss ?? 0) >= min;
    }

    private static AlertPreferenceDto ToDto(AlertPreference p) =>
        new(p.MinSeverity, p.AlwaysAlertKnownExploited, p.MinEpss, p.IncludeIncidents, p.Mode);

    private static AlertChannelDto ToDto(AlertChannel c) =>
        new(c.Id, c.Type, c.Label, c.TargetHint, c.IsEnabled, c.LastDeliveredAt, c.LastError);

    private static string Truncate(string value, int max) =>
        value.Length <= max ? value : value[..(max - 1)] + "…";
}
