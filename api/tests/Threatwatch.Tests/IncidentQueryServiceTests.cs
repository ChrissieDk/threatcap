using Microsoft.EntityFrameworkCore;
using Threatwatch.Core.Data;
using Threatwatch.Core.Entities;
using Threatwatch.Core.Enums;
using Threatwatch.Core.Services;

namespace Threatwatch.Tests;

public class IncidentQueryServiceTests : IDisposable
{
    private readonly ThreatwatchDbContext _db;
    private readonly IncidentQueryService _incidents;
    private readonly DashboardService _dashboard;
    private readonly Guid _userId = Guid.NewGuid();
    private readonly Guid _reactId = Guid.NewGuid();
    private readonly Guid _githubId = Guid.NewGuid();

    public IncidentQueryServiceTests()
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
        _db.Technologies.AddRange(
            new Technology
            {
                Id = _reactId,
                Name = "React",
                Slug = "react",
                Type = TechnologyType.Framework,
                Ecosystem = Ecosystem.Npm,
                Aliases = [],
            },
            new Technology
            {
                Id = _githubId,
                Name = "GitHub",
                Slug = "github",
                Type = TechnologyType.Infrastructure,
                Aliases = [],
            });
        _db.SaveChanges();
        var follows = new FollowService(_db);
        _incidents = new IncidentQueryService(_db, follows);
        _dashboard = new DashboardService(_db, follows);
    }

    public void Dispose() => _db.Dispose();

    [Fact]
    public async Task FollowingReactIncludesNpmRegistryIncidentsAndExcludesUnrelatedVendors()
    {
        SeedIncident("npm:1", "npm", "npm", Ecosystem.Npm, IncidentStatus.Investigating);
        SeedIncident("github:1", "github", "GitHub", null, IncidentStatus.Investigating);
        SeedIncident("cloudflare:1", "cloudflare", "Cloudflare", null, IncidentStatus.Investigating);
        await _db.SaveChangesAsync();
        _db.UserFollows.Add(new UserFollow
        {
            Id = Guid.NewGuid(),
            UserId = _userId,
            TechnologyId = _reactId,
            CreatedAt = DateTimeOffset.UtcNow,
        });
        await _db.SaveChangesAsync();

        var list = await _incidents.ListAsync(30, 50, following: true, _userId, CancellationToken.None);

        var item = Assert.Single(list);
        Assert.Equal("npm", item.VendorSlug);
    }

    [Fact]
    public async Task FollowingGitHubDoesNotPullNpmIncidents()
    {
        SeedIncident("npm:1", "npm", "npm", Ecosystem.Npm, IncidentStatus.Investigating);
        SeedIncident("github:1", "github", "GitHub", null, IncidentStatus.Investigating);
        await _db.SaveChangesAsync();
        _db.UserFollows.Add(new UserFollow
        {
            Id = Guid.NewGuid(),
            UserId = _userId,
            TechnologyId = _githubId,
            CreatedAt = DateTimeOffset.UtcNow,
        });
        await _db.SaveChangesAsync();

        var list = await _incidents.ListAsync(30, 50, following: true, _userId, CancellationToken.None);
        var item = Assert.Single(list);
        Assert.Equal("github", item.VendorSlug);
    }

    [Fact]
    public async Task ActiveIncidentsStayVisibleAfterTheDayWindow()
    {
        var old = DateTimeOffset.UtcNow.AddDays(-80);
        SeedIncident("npm:old", "npm", "npm", Ecosystem.Npm, IncidentStatus.Investigating, old);
        await _db.SaveChangesAsync();
        _db.UserFollows.Add(new UserFollow
        {
            Id = Guid.NewGuid(),
            UserId = _userId,
            TechnologyId = _reactId,
            CreatedAt = DateTimeOffset.UtcNow,
        });
        await _db.SaveChangesAsync();

        var list = await _incidents.ListAsync(30, 50, following: true, _userId, CancellationToken.None);
        Assert.Single(list);
    }

    [Fact]
    public async Task DashboardActiveCountIsFollowScoped()
    {
        SeedIncident("npm:1", "npm", "npm", Ecosystem.Npm, IncidentStatus.Investigating);
        SeedIncident("github:1", "github", "GitHub", null, IncidentStatus.Investigating);
        await _db.SaveChangesAsync();
        _db.UserFollows.Add(new UserFollow
        {
            Id = Guid.NewGuid(),
            UserId = _userId,
            TechnologyId = _reactId,
            CreatedAt = DateTimeOffset.UtcNow,
        });
        await _db.SaveChangesAsync();

        var scoped = await _dashboard.GetSummaryAsync(7, _userId, following: true, CancellationToken.None);
        var all = await _dashboard.GetSummaryAsync(7, _userId, following: false, CancellationToken.None);

        Assert.Equal(1, scoped.ActiveIncidents);
        Assert.Equal(2, all.ActiveIncidents);
    }

    private void SeedIncident(
        string externalId,
        string vendorSlug,
        string vendorName,
        Ecosystem? ecosystem,
        IncidentStatus status,
        DateTimeOffset? startedAt = null)
    {
        var now = DateTimeOffset.UtcNow;
        _db.SecurityIncidents.Add(new SecurityIncident
        {
            Id = Guid.NewGuid(),
            ExternalId = externalId,
            VendorSlug = vendorSlug,
            VendorName = vendorName,
            Ecosystem = ecosystem,
            Title = $"{vendorName} incident",
            Type = IncidentType.Outage,
            Status = status,
            SourceType = SourceType.StatusPage,
            StartedAt = startedAt ?? now,
            CreatedAt = now,
            UpdatedAt = now,
        });
    }
}
