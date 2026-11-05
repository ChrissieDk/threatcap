using System.Net;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Threatwatch.Core.Alerts;
using Threatwatch.Core.Data;
using Threatwatch.Core.Entities;
using Threatwatch.Core.Enums;
using Threatwatch.Ingestion.Alerts;

namespace Threatwatch.Tests;

public class OutboundUrlPolicyTests
{
    [Theory]
    [InlineData("https://hooks.slack.com/services/T0/B0/xyz")]
    [InlineData("https://ntfy.sh/my-topic")]
    public void Accepts_public_https(string url) =>
        Assert.True(OutboundUrlPolicy.TryParse(url, allowPrivate: false, out _, out _));

    [Theory]
    [InlineData("http://example.com/hook")]
    [InlineData("https://localhost/hook")]
    [InlineData("https://127.0.0.1/hook")]
    [InlineData("https://169.254.169.254/latest/meta-data")]
    [InlineData("https://10.0.0.5/hook")]
    [InlineData("https://[::1]/hook")]
    [InlineData("https://[::ffff:192.168.1.1]/hook")]
    [InlineData("https://user:pass@example.com/hook")]
    [InlineData("ftp://example.com/hook")]
    [InlineData("not a url")]
    [InlineData("")]
    public void Rejects_unsafe_urls(string url) =>
        Assert.False(OutboundUrlPolicy.TryParse(url, allowPrivate: false, out _, out _));

    [Fact]
    public void Private_targets_allowed_when_opted_in() =>
        Assert.True(OutboundUrlPolicy.TryParse("http://192.168.1.10:8080/topic", allowPrivate: true, out _, out _));

    [Theory]
    [InlineData("8.8.8.8", true)]
    [InlineData("100.64.0.1", false)]
    [InlineData("172.16.0.1", false)]
    [InlineData("172.32.0.1", true)]
    [InlineData("fd00::1", false)]
    [InlineData("fe80::1", false)]
    [InlineData("2606:4700:4700::1111", true)]
    public void Classifies_addresses(string ip, bool isPublic) =>
        Assert.Equal(isPublic, OutboundUrlPolicy.IsPublicAddress(IPAddress.Parse(ip)));
}

public class AlertServiceTests : IDisposable
{
    private readonly ThreatwatchDbContext _db;
    private readonly AlertService _alerts;
    private readonly Guid _userId = Guid.NewGuid();
    private readonly Technology _lodash;

    public AlertServiceTests()
    {
        _db = new ThreatwatchDbContext(new DbContextOptionsBuilder<ThreatwatchDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString()).Options);
        _alerts = new AlertService(_db, new EphemeralDataProtectionProvider(), Options.Create(new AlertOptions()));

        _db.Users.Add(new UserAccount
        {
            Id = _userId, Email = "dev@example.com", UserName = "dev@example.com",
            DisplayName = "Dev", CreatedAt = DateTimeOffset.UtcNow,
        });
        _lodash = new Technology
        {
            Id = Guid.NewGuid(), Name = "lodash", Slug = "pkg-lodash",
            Type = TechnologyType.Package, Ecosystem = Ecosystem.Npm, Aliases = [],
        };
        _db.Technologies.Add(_lodash);
        _db.UserFollows.Add(new UserFollow
        {
            Id = Guid.NewGuid(), UserId = _userId, TechnologyId = _lodash.Id, CreatedAt = DateTimeOffset.UtcNow,
        });
        _db.SaveChanges();
    }

    public void Dispose() => _db.Dispose();

    private async Task<AlertChannel> AddWebhookAsync()
    {
        _db.AlertPreferences.Add(new AlertPreference
        {
            Id = Guid.NewGuid(), UserId = _userId, MinSeverity = Severity.High,
            CreatedAt = DateTimeOffset.UtcNow.AddDays(-1), UpdatedAt = DateTimeOffset.UtcNow,
        });
        var channel = new AlertChannel
        {
            Id = Guid.NewGuid(), UserId = _userId, Type = AlertChannelType.Webhook,
            Label = "hook", CreatedAt = DateTimeOffset.UtcNow,
        };
        _db.AlertChannels.Add(channel);
        await _db.SaveChangesAsync();
        return channel;
    }

    private Vulnerability AddVuln(string id, string package, Severity severity, bool kev = false)
    {
        var v = new Vulnerability
        {
            Id = Guid.NewGuid(), CanonicalId = id, Title = id, Severity = severity,
            IsKnownExploited = kev, PublishedAt = DateTimeOffset.UtcNow.AddHours(-1),
            ModifiedAt = DateTimeOffset.UtcNow, CreatedAt = DateTimeOffset.UtcNow, UpdatedAt = DateTimeOffset.UtcNow,
        };
        v.AffectedPackages.Add(new AffectedPackage
        {
            Id = Guid.NewGuid(), VulnerabilityId = v.Id, Ecosystem = Ecosystem.Npm,
            PackageName = package, DisplayName = package,
        });
        _db.Vulnerabilities.Add(v);
        _db.SaveChanges();
        return v;
    }

    [Fact]
    public async Task Enqueues_matching_items_once()
    {
        await AddWebhookAsync();
        AddVuln("GHSA-hit", "lodash", Severity.Critical);
        AddVuln("GHSA-low", "lodash", Severity.Low);
        AddVuln("GHSA-other", "express", Severity.Critical);

        Assert.Equal(1, await _alerts.EnqueueAsync(default));
        Assert.Equal(0, await _alerts.EnqueueAsync(default));
        Assert.Single(_db.AlertDeliveries);
    }

    [Fact]
    public async Task Skips_disabled_channels()
    {
        var channel = await AddWebhookAsync();
        channel.IsEnabled = false;
        await _db.SaveChangesAsync();
        AddVuln("GHSA-hit", "lodash", Severity.Critical);

        Assert.Equal(0, await _alerts.EnqueueAsync(default));
    }

    [Fact]
    public async Task Kev_alerts_below_severity_threshold()
    {
        await AddWebhookAsync();
        AddVuln("GHSA-kev", "lodash", Severity.Low, kev: true);

        Assert.Equal(1, await _alerts.EnqueueAsync(default));
    }

    [Fact]
    public async Task Does_not_backfill_items_older_than_preferences()
    {
        await AddWebhookAsync();
        var pref = _db.AlertPreferences.Single();
        pref.CreatedAt = DateTimeOffset.UtcNow;
        await _db.SaveChangesAsync();
        AddVuln("GHSA-old", "lodash", Severity.Critical);

        Assert.Equal(0, await _alerts.EnqueueAsync(default));
    }

    [Fact]
    public async Task Rejects_private_webhook_and_encrypts_valid_target()
    {
        var (bad, error) = await _alerts.AddChannelAsync(
            _userId, new CreateAlertChannelRequest(AlertChannelType.Webhook, "x", "https://127.0.0.1/hook"), false, default);
        Assert.Null(bad);
        Assert.NotNull(error);

        var (ok, _) = await _alerts.AddChannelAsync(
            _userId, new CreateAlertChannelRequest(AlertChannelType.Webhook, "x", "https://1.1.1.1/hook"), false, default);
        Assert.NotNull(ok);
        var stored = _db.AlertChannels.Single(c => c.Id == ok!.Id);
        Assert.DoesNotContain("1.1.1.1", stored.ProtectedTarget);
        Assert.Equal("https://1.1.1.1/hook", _alerts.Unprotect(stored));
    }

    [Fact]
    public async Task Email_channel_requires_smtp_verification_and_channels_are_capped()
    {
        var (unverified, unverifiedError) = await _alerts.AddChannelAsync(
            _userId, new CreateAlertChannelRequest(AlertChannelType.Email, null, null), emailAvailable: true, default);
        Assert.Null(unverified);
        Assert.Contains("Verify", unverifiedError);

        _db.Users.Single(u => u.Id == _userId).EmailConfirmed = true;
        await _db.SaveChangesAsync();

        var (none, error) = await _alerts.AddChannelAsync(
            _userId, new CreateAlertChannelRequest(AlertChannelType.Email, null, null), emailAvailable: false, default);
        Assert.Null(none);
        Assert.NotNull(error);

        for (var i = 0; i < AlertOptions.MaxChannelsPerUser; i++)
        {
            var (c, _) = await _alerts.AddChannelAsync(
                _userId, new CreateAlertChannelRequest(AlertChannelType.Email, null, null), emailAvailable: true, default);
            Assert.NotNull(c);
        }

        var (extra, _) = await _alerts.AddChannelAsync(
            _userId, new CreateAlertChannelRequest(AlertChannelType.Email, null, null), emailAvailable: true, default);
        Assert.Null(extra);
    }

    [Fact]
    public async Task Dispatcher_sends_one_message_then_backs_off_and_disables_on_failure()
    {
        var channel = await AddWebhookAsync();
        AddVuln("GHSA-a", "lodash", Severity.Critical);
        AddVuln("GHSA-b", "lodash", Severity.High);
        await _alerts.EnqueueAsync(default);

        var sender = new FakeSender();
        var dispatcher = new AlertDispatcher(_db, _alerts, [sender], Options.Create(new AlertOptions()), NullLogger<AlertDispatcher>.Instance);

        Assert.Equal(1, await dispatcher.DeliverPendingAsync(default));
        Assert.Equal(2, sender.Messages.Single().Items.Count);
        Assert.All(_db.AlertDeliveries, d => Assert.NotNull(d.SentAt));
        Assert.Equal(0, await dispatcher.DeliverPendingAsync(default));

        sender.Fail = true;
        AddVuln("GHSA-c", "lodash", Severity.Critical);
        await _alerts.EnqueueAsync(default);
        for (var i = 0; i < AlertDispatcher.MaxConsecutiveFailures; i++)
        {
            foreach (var d in _db.AlertDeliveries.Where(d => d.SentAt == null)) d.NextAttemptAt = DateTimeOffset.UtcNow.AddMinutes(-1);
            await _db.SaveChangesAsync();
            await dispatcher.DeliverPendingAsync(default);
        }

        var reloaded = _db.AlertChannels.Single(c => c.Id == channel.Id);
        Assert.False(reloaded.IsEnabled);
        Assert.NotNull(reloaded.LastError);
    }

    [Fact]
    public async Task Ntfy_without_target_generates_secret_topic_and_exposes_setup()
    {
        var (channel, error) = await _alerts.AddChannelAsync(
            _userId, new CreateAlertChannelRequest(AlertChannelType.Ntfy, null, null), false, default);
        Assert.Null(error);

        var setup = await _alerts.GetNtfySetupAsync(_userId, channel!.Id, default);
        Assert.NotNull(setup);
        Assert.StartsWith("https://ntfy.sh/threatwatch-", setup.TopicUrl);
        Assert.Equal(12 + 32, setup.Topic.Length);
        Assert.Null(await _alerts.GetNtfySetupAsync(Guid.NewGuid(), channel.Id, default));
    }

    [Fact]
    public async Task Push_channel_validates_endpoint_and_refreshes_same_endpoint()
    {
        var (bad, error) = await _alerts.AddPushChannelAsync(
            _userId, new CreatePushChannelRequest("https://127.0.0.1/push", "key", "auth", null), default);
        Assert.Null(bad);
        Assert.NotNull(error);

        var request = new CreatePushChannelRequest("https://1.1.1.1/push/abc", "p256dh-key", "auth-secret", "Firefox");
        var (first, _) = await _alerts.AddPushChannelAsync(_userId, request, default);
        var (second, _) = await _alerts.AddPushChannelAsync(_userId, request, default);
        Assert.NotNull(first);
        Assert.Equal(first.Id, second!.Id);
        Assert.Single(_db.AlertChannels);
        Assert.DoesNotContain("1.1.1.1", _db.AlertChannels.Single().ProtectedTarget);
        Assert.Equal("auth-secret", _alerts.ReadPushTarget(_db.AlertChannels.Single())!.Auth);
    }

    [Fact]
    public async Task Permanent_failure_disables_channel_immediately()
    {
        var channel = await AddWebhookAsync();
        AddVuln("GHSA-a", "lodash", Severity.Critical);
        await _alerts.EnqueueAsync(default);

        var dispatcher = new AlertDispatcher(
            _db, _alerts, [new FakeSender { Permanent = true, Fail = true }],
            Options.Create(new AlertOptions()), NullLogger<AlertDispatcher>.Instance);
        await dispatcher.DeliverPendingAsync(default);

        Assert.False(_db.AlertChannels.Single(c => c.Id == channel.Id).IsEnabled);
    }

    private sealed class FakeSender : IAlertSender
    {
        public bool Fail { get; set; }
        public bool Permanent { get; set; }
        public List<AlertMessage> Messages { get; } = [];
        public AlertChannelType Type => AlertChannelType.Webhook;

        public Task SendAsync(AlertChannel channel, string? target, string? recipientEmail, AlertMessage message, CancellationToken ct)
        {
            if (Fail) throw new AlertSendException("boom", Permanent);
            Messages.Add(message);
            return Task.CompletedTask;
        }
    }
}
