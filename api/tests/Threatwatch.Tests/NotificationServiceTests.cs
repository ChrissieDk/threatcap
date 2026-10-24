using Microsoft.EntityFrameworkCore;
using Threatwatch.Core.Data;
using Threatwatch.Core.Entities;
using Threatwatch.Core.Enums;
using Threatwatch.Core.Services;

namespace Threatwatch.Tests;

public class NotificationServiceTests : IDisposable
{
    private readonly ThreatwatchDbContext _db;
    private readonly NotificationService _notifications;
    private readonly Guid _userId = Guid.NewGuid();
    private readonly Technology _lodash;

    public NotificationServiceTests()
    {
        var options = new DbContextOptionsBuilder<ThreatwatchDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        _db = new ThreatwatchDbContext(options);

        _db.Users.Add(new UserAccount
        {
            Id = _userId,
            Email = "dev@example.com",
            UserName = "dev@example.com",
            DisplayName = "Dev",
            CreatedAt = DateTimeOffset.UtcNow,
        });

        _lodash = new Technology
        {
            Id = Guid.NewGuid(),
            Name = "lodash",
            Slug = "pkg-lodash",
            Type = TechnologyType.Package,
            Ecosystem = Ecosystem.Npm,
            Aliases = [],
        };
        _db.Technologies.Add(_lodash);
        _db.UserFollows.Add(new UserFollow
        {
            Id = Guid.NewGuid(),
            UserId = _userId,
            TechnologyId = _lodash.Id,
            CreatedAt = DateTimeOffset.UtcNow,
        });

        // Matches the lodash follow (published after any cursor).
        AddVulnerability("GHSA-lodash-1", "lodash", Severity.High, publishedDaysAgo: 1);
        // Does not match the follow (different ecosystem).
        AddVulnerability("GHSA-other-1", "django", Severity.Critical, Ecosystem.PyPI, publishedDaysAgo: 1);
        // Matches but published long ago; only surfaces via KEV event.
        var kevVuln = AddVulnerability("GHSA-lodash-2", "lodash", Severity.Critical, publishedDaysAgo: 400);
        kevVuln.IsKnownExploited = true;
        _db.VulnerabilityEvents.Add(new VulnerabilityEvent
        {
            Id = Guid.NewGuid(),
            VulnerabilityId = kevVuln.Id,
            EventType = VulnerabilityEventType.KnownExploitedAdded,
            EventAt = DateTimeOffset.UtcNow.AddDays(-2),
            IngestedAt = DateTimeOffset.UtcNow,
        });

        _db.SaveChanges();
        _notifications = new NotificationService(_db);
    }

    public void Dispose() => _db.Dispose();

    [Fact]
    public async Task ReturnsOnlyFollowedMatchesIncludingRecentKevAdditions()
    {
        var summary = await _notifications.GetAsync(_userId, CancellationToken.None);

        var ids = summary.Items.Select(i => i.CanonicalId).OrderBy(x => x).ToArray();
        Assert.Equal(["GHSA-lodash-1", "GHSA-lodash-2"], ids);
        Assert.All(summary.Items, i => Assert.Equal("lodash", i.MatchedTechnologyName));
        Assert.True(summary.HasKevUnread);
        Assert.Equal(2, summary.UnreadCount);
    }

    [Fact]
    public async Task OldKevAdditionBeforeCursorIsNotUnread()
    {
        var user = await _db.Users.FindAsync(_userId);
        user!.LastNotificationsReadAt = DateTimeOffset.UtcNow.AddDays(-1);
        await _db.SaveChangesAsync();

        var summary = await _notifications.GetAsync(_userId, CancellationToken.None);

        // The 400-day-old vulnerability published before the cursor drops out entirely;
        // the 2-day-old KEV event is before the cursor too, so nothing is unread.
        Assert.Equal(0, summary.UnreadCount);
        Assert.DoesNotContain(summary.Items, i => i.CanonicalId == "GHSA-lodash-1");
    }

    [Fact]
    public async Task MarkAllReadMovesTheCursorAndZeroesUnread()
    {
        var before = await _notifications.GetAsync(_userId, CancellationToken.None);
        Assert.True(before.UnreadCount > 0);

        var after = await _notifications.MarkAllReadAsync(_userId, CancellationToken.None);

        Assert.Equal(0, after.UnreadCount);
        var user = await _db.Users.FindAsync(_userId);
        Assert.NotNull(user!.LastNotificationsReadAt);
    }

    [Fact]
    public async Task UserWithoutFollowsGetsEmptySummary()
    {
        var lonely = Guid.NewGuid();
        _db.Users.Add(new UserAccount
        {
            Id = lonely,
            Email = "lonely@example.com",
            UserName = "lonely@example.com",
            DisplayName = "Lonely",
            CreatedAt = DateTimeOffset.UtcNow,
        });
        await _db.SaveChangesAsync();

        var summary = await _notifications.GetAsync(lonely, CancellationToken.None);

        Assert.Equal(0, summary.UnreadCount);
        Assert.Empty(summary.Items);
    }

    private Vulnerability AddVulnerability(
        string canonicalId, string packageName, Severity severity,
        Ecosystem ecosystem = Ecosystem.Npm, int publishedDaysAgo = 1)
    {
        var vuln = new Vulnerability
        {
            Id = Guid.NewGuid(),
            CanonicalId = canonicalId,
            Title = $"Vulnerability in {packageName}",
            Severity = severity,
            IsKnownExploited = false,
            PublishedAt = DateTimeOffset.UtcNow.AddDays(-publishedDaysAgo),
            ModifiedAt = DateTimeOffset.UtcNow.AddDays(-publishedDaysAgo),
            CreatedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow,
        };
        vuln.AffectedPackages.Add(new AffectedPackage
        {
            Id = Guid.NewGuid(),
            VulnerabilityId = vuln.Id,
            Ecosystem = ecosystem,
            PackageName = packageName,
            DisplayName = packageName,
            FixedVersions = [],
            Vulnerability = vuln,
        });
        _db.Vulnerabilities.Add(vuln);
        return vuln;
    }
}
